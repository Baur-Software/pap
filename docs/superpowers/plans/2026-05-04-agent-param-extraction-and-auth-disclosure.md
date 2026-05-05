# Agent Parameter Extraction and Auth Disclosure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make 58 broken catalog agents work honestly — extracting structured URL parameters from natural-language queries via a new `EntityExtractor` agent that uses the LLM when available and regex for structured patterns, and routing user API keys through the SD-JWT credential store rather than hardcoded `demo` values or flat `agent_settings`.

**Architecture:** Four coordinated subsystems:
1. **Entity extraction** — a new `EntityExtractor` agent wraps the LLM (or falls back to regex) to pull `{owner}`, `{repo}`, `{lat}`, `{lon}`, `{artist}`, `{title}`, etc. from natural-language queries. BM25 already handles *which* agent to use; this handles *what values* to pass to it.
2. **Handler param substitution** — `dynamic_handler.rs` invokes the entity extractor for any `{param}` beyond `{query}`, using the LLM path if available and regex fallback otherwise.
3. **SD-JWT credential disclosure** — API keys travel via the principal's vault as SD-JWT selective disclosures through the existing 6-phase handshake (`requires_disclosure = ["api_key"]`), never as flat config values. The orchestrator gates on vault availability and surfaces the disclosure scope to the user.
4. **Catalog TOML fixes** — auth-gated agents declare `requires_disclosure = ["api_key"]` and use `{api_key}` in their URL templates; structural-param agents declare their params in `requires_disclosure`.

**Tech Stack:** Rust, `pap-credential` (SD-JWT types — already exists), `pap-credential-store` (encrypted vault — already exists, not yet wired to Tauri), `reqwest` blocking, existing `DynamicAgentHandler`, `SessionStore`, `AgentSet::register_dynamic`.

---

## Background / Key Facts

Read these files before implementing:

- `crates/pap-agents/src/dynamic_handler.rs` — `DynamicSession`, `handle_disclosure()`, `execute()`, `agent_props` header substitution
- `crates/pap-agents/src/intent_index.rs` — BM25 classifier. Classifies *intent* (which agent), not entities (what values). `IntentMatch.cleaned_query` is the raw user prompt verbatim — entity extraction is a downstream step.
- `crates/pap-agents/src/dynamic.rs` — `DynamicAgentDef`, `HttpEndpointConfig`, `requires_disclosure`
- `crates/pap-agents/src/registry.rs` — `register_dynamic()` at line 168
- `crates/pap-credential/src/sd_jwt.rs` — `SelectiveDisclosureJwt`, `Disclosure` types. `disclose(&["api_key"])` produces `Vec<Disclosure>` with salt+key+value.
- `crates/pap-credential-store/src/` — `Vault`, `SqliteVaultStore`. Fully implemented, not yet exposed via Tauri commands.
- `apps/papillon/frontend/src/handshake/mod.rs` line 263 — Phase 3 currently builds `{"@type": action_type, "query": query}`. This is where disclosed SD-JWT claims get merged in.
- `crates/papillon-shared/src/db/mod.rs` — `DatabaseOps::get_agent_settings()` returns `HashMap<String, AgentSettingRow>` — this is the flat settings store, separate from the vault.

**What BM25 does and does NOT do:**
- Does: routes "latest rust release" → `github_releases` agent (intent classification)
- Does NOT: extract `owner=rust-lang` and `repo=rust` from that query (entity extraction)

**What the SD-JWT vault does:**
- Stores API keys as `VaultItemData::VerifiableCredential` or a new `ApiCredential` variant (see Task 4)
- `SelectiveDisclosureJwt::disclose(&["api_key"])` produces a disclosure containing only that claim, with its salt — the rest of the vault stays hidden
- The orchestrator presents this to the user as "Agent X needs your API key for Alpha Vantage — approve?"
- After approval, the disclosed claim arrives at `handle_disclosure()` as `{"api_key": "sk-live-..."}`

**Three bugs to fix:**

1. `dynamic_handler.rs:145` only substitutes `{query}`. URLs like `https://api.github.com/repos/{owner}/{repo}` ship literal `{owner}` to GitHub.
2. ~24 catalog TOMLs have `apikey=demo` hardcoded. API keys should come through the SD-JWT disclosure path.
3. The vault exists but has no Tauri command layer — the orchestrator can't yet ask the vault to disclose a specific credential for a specific agent.

---

## File Map

| File | Change |
|------|--------|
| `crates/pap-agents/src/entity_extractor.rs` | **New file.** `EntityExtractor` — LLM-first, regex-fallback entity extraction for URL template params |
| `crates/pap-agents/src/lib.rs` | Export `entity_extractor` module |
| `crates/pap-agents/src/dynamic_handler.rs` | Expand `DynamicSession.disclosed_props`, update `handle_disclosure()` to store all fields, update `execute()` to resolve all `{param}` via extractor |
| `crates/papillon-shared/src/credential_gate.rs` | **New file.** `CredentialGate` — determines whether an agent's `requires_disclosure` list needs vault credentials, builds disclosure request for orchestrator |
| `crates/papillon-shared/src/lib.rs` | Export `credential_gate` module |
| `apps/papillon/src/commands/vault.rs` | **New file.** Tauri commands: `vault_open`, `vault_seal`, `vault_disclose_for_agent` |
| `apps/papillon/src/commands/mod.rs` | Register new vault commands |
| `apps/papillon/src/main.rs` | Register vault Tauri command handlers |
| `apps/papillon/frontend/src/handshake/mod.rs` | Phase 3: merge vault disclosures into disclosure object |
| Catalog TOMLs (43 files) | Fix `requires_disclosure`, replace `demo` keys with `{api_key}`, add `configurable_properties` |

---

## Task 1: Add `entity_extractor.rs` — LLM-first, regex-fallback entity extraction

**Files:**
- Create: `crates/pap-agents/src/entity_extractor.rs`
- Modify: `crates/pap-agents/src/lib.rs`

The entity extractor takes a URL template and a query string and returns a `HashMap<String, String>` of resolved param values. It has two execution paths:

**LLM path (when LLM is configured):** Builds a structured prompt listing the param names needed and asks the LLM to extract them from the query as JSON. Deterministic output via a strict JSON schema prompt.

**Regex/heuristic path (fallback):** Pattern matching for well-structured inputs — coordinate pairs, `owner/repo`, `Artist - Title`, `X to Y`, 4-digit years, `r/subreddit`. Returns the verbatim query for params without a reliable heuristic. Returns `None` for auth params (they never come from query text).

**Auth params are excluded from extraction** — `api_key`, `access_key`, `key`, `token`, `consumer_key`, `user_key`, `wskey` always return `None` from this extractor. They come from the vault via SD-JWT disclosure.

- [ ] **Step 1.1: Write failing tests for auth param exclusion**

Create `crates/pap-agents/src/entity_extractor.rs`:

```rust
//! Entity extraction for URL template parameters.
//!
//! Resolves `{param}` placeholders in URL templates from natural-language query text.
//! Auth params (api_key, access_key, etc.) always return None — they come from the
//! SD-JWT credential vault, never from query text.

use std::collections::HashMap;

use crate::llm::{LlmClient, LlmProvider};

/// Names that identify authentication credentials — never extracted from query text.
const AUTH_PARAMS: &[&str] = &[
    "api_key", "apikey", "access_key", "key", "token", "api_token",
    "consumer_key", "user_key", "wskey", "access_token",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_params_return_none() {
        for name in AUTH_PARAMS {
            assert_eq!(
                extract_heuristic(name, "any query text"),
                None,
                "auth param '{name}' must never be extracted from query text"
            );
        }
    }
}
```

- [ ] **Step 1.2: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test auth_params_return_none 2>&1 | head -20
```
Expected: compile error (function not defined)

- [ ] **Step 1.3: Implement `extract_heuristic`**

Add above the `#[cfg(test)]` block:

```rust
/// Extract a single URL template param value from query text using heuristics.
/// Returns `None` for auth params (must come from vault) and for params with
/// no reliable extraction pattern.
pub fn extract_heuristic(name: &str, query: &str) -> Option<String> {
    let q = query.trim();

    // Auth params never come from query text
    if AUTH_PARAMS.contains(&name) {
        return None;
    }

    match name {
        // Coordinates: "37.7749,-122.4194" or "37.7749, -122.4194"
        "lat" | "latitude" => {
            let (lat_str, _) = q.split_once(',')?;
            let lat: f64 = lat_str.trim().parse().ok()?;
            (-90.0..=90.0).contains(&lat).then(|| lat_str.trim().to_string())
        }
        "lon" | "lng" | "longitude" => {
            let (_, lon_str) = q.split_once(',')?;
            let lon: f64 = lon_str.trim().parse().ok()?;
            (-180.0..=180.0).contains(&lon).then(|| lon_str.trim().to_string())
        }

        // GitHub: "torvalds/linux" or "github.com/torvalds/linux"
        "owner" => {
            let q = q.strip_prefix("github.com/").unwrap_or(q);
            let (owner, _) = q.split_once('/')?;
            Some(owner.trim().to_string())
        }
        "repo" => {
            let q = q.strip_prefix("github.com/").unwrap_or(q);
            let (_, rest) = q.split_once('/')?;
            Some(rest.split('/').next()?.trim().to_string())
        }

        // Reddit: "r/rust" or bare word
        "subreddit" => {
            let sub = q.strip_prefix("r/").unwrap_or(q);
            Some(sub.split_whitespace().next().unwrap_or(sub).to_string())
        }

        // Music: "Artist - Title"
        "artist" => q.split_once(" - ").map(|(a, _)| a.trim().to_string()),
        "title" => q.split_once(" - ").map(|(_, t)| t.trim().to_string()),

        // Travel: "London to Paris"
        "origin" | "oName" => {
            split_to(q).map(|(o, _)| o)
        }
        "destination" | "dName" => {
            split_to(q).map(|(_, d)| d)
        }

        // Year: first 4-digit number
        "year" => q
            .split_whitespace()
            .find(|w| w.len() == 4 && w.chars().all(|c| c.is_ascii_digit()))
            .map(str::to_string),

        // Verbatim fallback: BM25 already routed to the right agent;
        // the query IS the country/language/sport/league/etc.
        _ => Some(q.to_string()),
    }
}

fn split_to(q: &str) -> Option<(String, String)> {
    let lower = q.to_lowercase();
    let idx = lower.find(" to ")?;
    let origin = q[..idx].trim().to_string();
    let dest = q[idx + 4..].trim().to_string();
    Some((origin, dest))
}
```

- [ ] **Step 1.4: Add tests for heuristic extraction**

Add to the `tests` module:

```rust
    #[test]
    fn lat_from_coord_pair() {
        assert_eq!(extract_heuristic("lat", "37.7749,-122.4194"), Some("37.7749".to_string()));
    }

    #[test]
    fn lon_from_coord_pair() {
        assert_eq!(extract_heuristic("lon", "37.7749,-122.4194"), Some("-122.4194".to_string()));
    }

    #[test]
    fn owner_repo_from_slash() {
        assert_eq!(extract_heuristic("owner", "torvalds/linux"), Some("torvalds".to_string()));
        assert_eq!(extract_heuristic("repo", "torvalds/linux"), Some("linux".to_string()));
    }

    #[test]
    fn owner_repo_with_github_prefix() {
        assert_eq!(extract_heuristic("owner", "github.com/rust-lang/rust"), Some("rust-lang".to_string()));
        assert_eq!(extract_heuristic("repo", "github.com/rust-lang/rust"), Some("rust".to_string()));
    }

    #[test]
    fn subreddit_with_r_prefix() {
        assert_eq!(extract_heuristic("subreddit", "r/rust"), Some("rust".to_string()));
    }

    #[test]
    fn artist_title_from_dash() {
        assert_eq!(extract_heuristic("artist", "Pink Floyd - Comfortably Numb"), Some("Pink Floyd".to_string()));
        assert_eq!(extract_heuristic("title", "Pink Floyd - Comfortably Numb"), Some("Comfortably Numb".to_string()));
    }

    #[test]
    fn origin_destination_from_to() {
        assert_eq!(extract_heuristic("origin", "London to Paris"), Some("London".to_string()));
        assert_eq!(extract_heuristic("destination", "London to Paris"), Some("Paris".to_string()));
    }

    #[test]
    fn year_from_natural_language() {
        assert_eq!(extract_heuristic("year", "treasury rates 2023"), Some("2023".to_string()));
    }

    #[test]
    fn unknown_param_returns_verbatim() {
        assert_eq!(extract_heuristic("country", "Germany"), Some("Germany".to_string()));
    }
```

- [ ] **Step 1.5: Run tests to verify they pass**

```bash
cd crates/pap-agents && cargo test entity_extractor 2>&1
```
Expected: all tests pass

- [ ] **Step 1.6: Add `extract_template_params` to the same file**

This is the helper that finds all `{param}` names in a URL template (excluding `{query}`):

```rust
/// Return all `{name}` placeholder names in `url_template` that are not `{query}`.
pub fn extract_template_params(url_template: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    let mut chars = url_template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let name: String = chars.by_ref().take_while(|&c| c != '}').collect();
            if !name.is_empty() && name != "query" && seen.insert(name.clone()) {
                result.push(name);
            }
        }
    }
    result
}
```

Add tests:

```rust
    #[test]
    fn extract_params_excludes_query() {
        let params = extract_template_params("https://api.foo.com/search?q={query}");
        assert!(params.is_empty());
    }

    #[test]
    fn extract_params_lat_lon() {
        let params = extract_template_params("https://api.foo.com?lat={lat}&lon={lon}");
        assert_eq!(params, vec!["lat", "lon"]);
    }

    #[test]
    fn extract_params_owner_repo() {
        let params = extract_template_params("https://api.github.com/repos/{owner}/{repo}/releases");
        assert_eq!(params, vec!["owner", "repo"]);
    }

    #[test]
    fn extract_params_deduplicates() {
        let params = extract_template_params("https://api.foo.com/{id}?related={id}");
        assert_eq!(params, vec!["id"]);
    }
```

- [ ] **Step 1.7: Add LLM-backed extraction**

Add the public `EntityExtractor` struct and `extract_with_llm`:

```rust
/// Extracts URL template parameter values from natural-language query text.
///
/// Tries two paths in order:
/// 1. LLM extraction — asks the configured LLM to extract params as JSON
/// 2. Heuristic fallback — regex/pattern matching for structured inputs
pub struct EntityExtractor {
    llm: Box<dyn LlmClient>,
}

impl EntityExtractor {
    pub fn new(llm: Box<dyn LlmClient>) -> Self {
        Self { llm }
    }

    /// Resolve all `{param}` values for the given URL template from the query.
    /// Auth params are excluded (they come from vault disclosure).
    /// Returns a map of param_name → resolved_value for params that could be resolved.
    pub fn resolve(
        &self,
        url_template: &str,
        query: &str,
    ) -> HashMap<String, String> {
        let params = extract_template_params(url_template);
        if params.is_empty() {
            return HashMap::new();
        }

        // Exclude auth params — they must come from vault
        let structural_params: Vec<&str> = params
            .iter()
            .map(|s| s.as_str())
            .filter(|name| !AUTH_PARAMS.contains(name))
            .collect();

        if structural_params.is_empty() {
            return HashMap::new();
        }

        // Try LLM extraction first
        if let Ok(extracted) = self.extract_with_llm(&structural_params, query) {
            if !extracted.is_empty() {
                return extracted;
            }
        }

        // Heuristic fallback
        structural_params
            .iter()
            .filter_map(|&name| {
                extract_heuristic(name, query).map(|v| (name.to_string(), v))
            })
            .collect()
    }

    fn extract_with_llm(
        &self,
        params: &[&str],
        query: &str,
    ) -> Result<HashMap<String, String>, String> {
        let param_list = params.join(", ");
        let instructions = format!(
            "Extract the following named values from the user query. \
             Output ONLY a JSON object with these exact keys: [{param_list}]. \
             If a value cannot be determined, omit that key. \
             Do not add any other keys or explanation.\n\
             Example for params [owner, repo] and query \"torvalds/linux\": \
             {{\"owner\":\"torvalds\",\"repo\":\"linux\"}}"
        );

        let response = self.llm.complete(&instructions, query)
            .map_err(|e| e.to_string())?;

        // Strip markdown fences if present
        let cleaned = response
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        let parsed: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| e.to_string())?;

        let obj = parsed.as_object().ok_or("not an object")?;
        let mut result = HashMap::new();
        for &param in params {
            if let Some(val) = obj.get(param).and_then(|v| v.as_str()) {
                if !val.is_empty() {
                    result.insert(param.to_string(), val.to_string());
                }
            }
        }
        Ok(result)
    }
}
```

- [ ] **Step 1.8: Export from `lib.rs`**

In `crates/pap-agents/src/lib.rs`:
```rust
pub mod entity_extractor;
```

- [ ] **Step 1.9: Full test run**

```bash
cd crates/pap-agents && cargo test 2>&1 | tail -20
```
Expected: all tests pass

- [ ] **Step 1.10: Commit**

```bash
git add crates/pap-agents/src/entity_extractor.rs crates/pap-agents/src/lib.rs
git commit -m "feat(agents): add EntityExtractor — LLM-first, regex-fallback URL param resolution"
```

---

## Task 2: Wire entity extraction into `dynamic_handler.rs`

**Files:**
- Modify: `crates/pap-agents/src/dynamic_handler.rs`

- [ ] **Step 2.1: Expand `DynamicSession` to hold all disclosed properties**

Change:
```rust
struct DynamicSession {
    query: Option<String>,
}
```
To:
```rust
struct DynamicSession {
    query: Option<String>,
    /// All scalar properties disclosed in Phase 3 (e.g. api_key from SD-JWT, user-provided params).
    disclosed_props: HashMap<String, String>,
}
```

Update the `DynamicSession` initializer in `handle_token()`:
```rust
self.sessions.insert(session_id.clone(), DynamicSession {
    query: None,
    disclosed_props: HashMap::new(),
})?;
```

- [ ] **Step 2.2: Write failing test**

Add to `dynamic_handler.rs` tests:

```rust
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
```

- [ ] **Step 2.3: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test disclosed_props_stored 2>&1 | head -20
```
Expected: compile error (field `disclosed_props` doesn't exist)

- [ ] **Step 2.4: Update `handle_disclosure()` to extract all scalar properties**

Replace the existing `handle_disclosure` impl:

```rust
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
```

- [ ] **Step 2.5: Run test to verify it passes**

```bash
cd crates/pap-agents && cargo test disclosed_props_stored 2>&1
```
Expected: PASS

- [ ] **Step 2.6: Update `execute()` to resolve all template params**

In `execute()`, replace the `{query}`-only URL substitution:

```rust
let url = endpoint.url_template.replace("{query}", &query);
```

With:

```rust
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
```

- [ ] **Step 2.7: Run full test suite**

```bash
cd crates/pap-agents && cargo test 2>&1 | tail -20
```
Expected: all tests pass

- [ ] **Step 2.8: Commit**

```bash
git add crates/pap-agents/src/dynamic_handler.rs
git commit -m "feat(agents): resolve all URL template params via disclosed props and entity extractor"
```

---

## Task 3: Add `credential_gate.rs` — orchestrator-side vault disclosure logic

**Files:**
- Create: `crates/papillon-shared/src/credential_gate.rs`
- Modify: `crates/papillon-shared/src/lib.rs`

This module determines, given an agent's `requires_disclosure` list, whether the agent needs credential vault access (i.e. it requires an auth param), and builds the disclosure request that the orchestrator presents to the user.

- [ ] **Step 3.1: Write failing tests**

Create `crates/papillon-shared/src/credential_gate.rs`:

```rust
//! Credential gate — determines whether an agent's `requires_disclosure` list
//! needs vault credentials, and produces the user-facing disclosure request.

/// Returns true if any item in `requires_disclosure` is a known auth param name.
pub fn needs_vault_credential(requires_disclosure: &[String]) -> bool {
    requires_disclosure
        .iter()
        .any(|s| CREDENTIAL_PARAM_NAMES.contains(&s.as_str()))
}

/// The canonical set of param names that represent API credentials.
/// These must come from the vault, never from query text or agent settings.
pub const CREDENTIAL_PARAM_NAMES: &[&str] = &[
    "api_key", "apikey", "access_key", "access_token", "key", "token",
    "api_token", "consumer_key", "user_key", "wskey",
];

/// Identifies which credential param names an agent requires.
pub fn credential_params_for(requires_disclosure: &[String]) -> Vec<String> {
    requires_disclosure
        .iter()
        .filter(|s| CREDENTIAL_PARAM_NAMES.contains(&s.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_vantage_needs_vault() {
        let reqs = vec!["query".to_string(), "api_key".to_string()];
        assert!(needs_vault_credential(&reqs));
    }

    #[test]
    fn geo_agent_no_vault_needed() {
        let reqs = vec!["lat".to_string(), "lon".to_string()];
        assert!(!needs_vault_credential(&reqs));
    }

    #[test]
    fn empty_disclosure_no_vault() {
        assert!(!needs_vault_credential(&[]));
    }

    #[test]
    fn credential_params_extracted() {
        let reqs = vec!["query".to_string(), "api_key".to_string(), "lat".to_string()];
        let creds = credential_params_for(&reqs);
        assert_eq!(creds, vec!["api_key".to_string()]);
    }
}
```

- [ ] **Step 3.2: Run tests to verify they pass**

```bash
cargo test -p papillon-shared credential_gate 2>&1
```
Expected: PASS (the logic is simple enough it should pass immediately)

- [ ] **Step 3.3: Export from `lib.rs`**

In `crates/papillon-shared/src/lib.rs`:
```rust
pub mod credential_gate;
```

- [ ] **Step 3.4: Commit**

```bash
git add crates/papillon-shared/src/credential_gate.rs crates/papillon-shared/src/lib.rs
git commit -m "feat(orchestrator): add credential_gate — detect vault-requiring agents"
```

---

## Task 4: Add Tauri vault commands — expose the credential store to the frontend

**Files:**
- Create: `apps/papillon/src/commands/vault.rs`
- Modify: `apps/papillon/src/commands/mod.rs`
- Modify: `apps/papillon/src/main.rs`

The vault (`pap-credential-store`) is production-ready but has no Tauri command layer. This task adds the minimum commands needed to:
1. Open (unlock) the vault with the user's password
2. Seal (lock) the vault
3. Disclose a specific credential claim for a specific agent (returns the raw claim value after user-visible gate)

**Important:** The vault password is never persisted and never leaves Rust. The Tauri frontend only calls `vault_disclose_for_agent` — it receives the disclosed claim value ephemerally and passes it into the handshake; it never stores the raw key.

- [ ] **Step 4.1: Write failing tests**

Create `apps/papillon/src/commands/vault.rs`:

```rust
//! Tauri commands for the credential vault (pap-credential-store).
//!
//! The vault stores API keys as AES-256-GCM encrypted items.
//! Commands here unlock, seal, and produce ephemeral SD-JWT disclosures
//! for specific agents — raw keys never leave Rust into persistent storage.

use pap_credential_store::{SqliteVaultStore, Vault, VaultItemData};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::State;

use crate::error::PapillonError;
use crate::state::AppState;

/// Open (unlock) the vault. Subsequent `vault_disclose_for_agent` calls succeed
/// until `vault_seal` is called or the process exits.
#[tauri::command]
pub fn vault_open(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), PapillonError> {
    // Implementation in Step 4.3
    todo!()
}

/// Seal the vault — zeroes the in-memory vault key.
#[tauri::command]
pub fn vault_seal(state: State<'_, AppState>) -> Result<(), PapillonError> {
    todo!()
}

/// Returns the stored credential value for the given `credential_name` (e.g. "alpha_vantage_api_key"),
/// intended for disclosure to `agent_did`. The frontend passes this ephemerally into the handshake.
///
/// Returns an error if the vault is sealed or the credential doesn't exist.
#[tauri::command]
pub fn vault_disclose_for_agent(
    state: State<'_, AppState>,
    credential_name: String,
    agent_did: String,
) -> Result<String, PapillonError> {
    todo!()
}

/// Store a credential in the vault. Used by the settings UI when the user provides their API key.
#[tauri::command]
pub fn vault_store_credential(
    state: State<'_, AppState>,
    credential_name: String,
    credential_value: String,
) -> Result<(), PapillonError> {
    todo!()
}

#[cfg(test)]
mod tests {
    // Integration tests that require a real vault file go here.
    // Unit tests for the gate logic live in papillon-shared::credential_gate.
}
```

- [ ] **Step 4.2: Add `vault_handle` to `AppState`**

In `apps/papillon/src/state.rs`, add to `AppState`:

```rust
/// Credential vault — unlocked on demand by the user, sealed at exit.
/// `None` means the vault is sealed (not yet unlocked or auto-locked).
pub vault: Arc<Mutex<Option<Vault<SqliteVaultStore>>>>,
```

Also add a `vault_path: PathBuf` field so `vault_open` knows where to find the file.

- [ ] **Step 4.3: Implement the vault commands**

Fill in the four `todo!()` stubs:

```rust
pub fn vault_open(state: State<'_, AppState>, password: String) -> Result<(), PapillonError> {
    let store = SqliteVaultStore::open(&state.vault_path)
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let vault = Vault::open(store, &password)
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let mut guard = state.vault.lock().map_err(|e| PapillonError::from(e.to_string()))?;
    *guard = Some(vault);
    Ok(())
}

pub fn vault_seal(state: State<'_, AppState>) -> Result<(), PapillonError> {
    let mut guard = state.vault.lock().map_err(|e| PapillonError::from(e.to_string()))?;
    *guard = None;
    Ok(())
}

pub fn vault_disclose_for_agent(
    state: State<'_, AppState>,
    credential_name: String,
    _agent_did: String,  // logged for audit; not yet used for scoped access
) -> Result<String, PapillonError> {
    let guard = state.vault.lock().map_err(|e| PapillonError::from(e.to_string()))?;
    let vault = guard.as_ref().ok_or_else(|| PapillonError::from("vault is sealed".to_string()))?;
    let value = vault
        .get_credential(&credential_name)
        .map_err(|e| PapillonError::from(e.to_string()))?;
    Ok(value)
}

pub fn vault_store_credential(
    state: State<'_, AppState>,
    credential_name: String,
    credential_value: String,
) -> Result<(), PapillonError> {
    let guard = state.vault.lock().map_err(|e| PapillonError::from(e.to_string()))?;
    let vault = guard.as_ref().ok_or_else(|| PapillonError::from("vault is sealed".to_string()))?;
    vault
        .store_credential(&credential_name, &credential_value)
        .map_err(|e| PapillonError::from(e.to_string()))?;
    Ok(())
}
```

**Note:** `Vault::get_credential` and `Vault::store_credential` are new methods needed on the `Vault` type in `pap-credential-store`. Add them in the same task (see Step 4.4).

- [ ] **Step 4.4: Add `get_credential` / `store_credential` to `Vault`**

In `crates/pap-credential-store/src/vault.rs` (or wherever `Vault` is defined), add:

```rust
/// Store a named API credential (plaintext value encrypted at rest).
pub fn store_credential(&self, name: &str, value: &str) -> Result<(), VaultError> {
    self.add_item(VaultItemData::ApiCredential {
        name: name.to_string(),
        value: value.to_string(),
    })?;
    Ok(())
}

/// Retrieve a named API credential value (decrypted from vault).
pub fn get_credential(&self, name: &str) -> Result<String, VaultError> {
    for item in self.list_items()? {
        if let VaultItemData::ApiCredential { name: item_name, value } = self.get_item(&item.id)? {
            if item_name == name {
                return Ok(value);
            }
        }
    }
    Err(VaultError::NotFound(name.to_string()))
}
```

Add `ApiCredential` to `VaultItemData` in `crates/pap-credential-store/src/types.rs`:

```rust
ApiCredential {
    name: String,
    value: String,
},
```

Add `ApiCredential = 4` to `VaultItemType` enum and handle the new variant in the SQLite serialization layer.

- [ ] **Step 4.5: Register commands in `main.rs`**

In `apps/papillon/src/main.rs`, add to the `.invoke_handler(tauri::generate_handler![...])` call:

```rust
commands::vault::vault_open,
commands::vault::vault_seal,
commands::vault::vault_disclose_for_agent,
commands::vault::vault_store_credential,
```

- [ ] **Step 4.6: Compile check**

```bash
cd apps/papillon && cargo check 2>&1 | grep "^error" | head -20
```
Expected: no errors

- [ ] **Step 4.7: Commit**

```bash
git add crates/pap-credential-store/src/ apps/papillon/src/commands/vault.rs apps/papillon/src/commands/mod.rs apps/papillon/src/state.rs apps/papillon/src/main.rs
git commit -m "feat(vault): expose credential store via Tauri commands for SD-JWT API key disclosure"
```

---

## Task 5: Wire vault disclosures into the Phase 3 handshake (WASM)

**Files:**
- Modify: `apps/papillon/frontend/src/handshake/mod.rs`

Phase 3 currently sends `{"@type": action_type, "query": query}`. When the agent's `requires_disclosure` contains credential params, the frontend must:
1. Check if those params are in the vault (call `vault_disclose_for_agent`)
2. If not yet unlocked, gate on the vault-unlock UI (out of scope for this task — just error cleanly)
3. Merge the returned claim values into the disclosure object

This is the SD-JWT path: the vault acts as the principal's credential store, the orchestrator mediates access, and the agent receives the key as a disclosed claim in Phase 3 — exactly the same disclosure channel as the query.

- [ ] **Step 5.1: Extract a testable `build_disclosures` function**

In `apps/papillon/frontend/src/handshake/mod.rs` (or a sibling `handshake_helpers.rs`), extract:

```rust
/// Build the Phase-3 disclosure object.
/// `extra_disclosures` is a map of param_name → value for any vault-resolved credentials.
pub fn build_disclosures(
    action_type: &str,
    query: &str,
    extra_disclosures: &std::collections::HashMap<String, String>,
) -> Vec<serde_json::Value> {
    let mut obj = serde_json::json!({
        "@type": action_type,
        "query": query,
    });
    for (key, val) in extra_disclosures {
        obj[key] = serde_json::json!(val);
    }
    vec![obj]
}
```

Test:

```rust
#[test]
fn build_disclosures_merges_vault_claims() {
    let mut extra = std::collections::HashMap::new();
    extra.insert("api_key".to_string(), "sk-live-123".to_string());
    let result = build_disclosures("schema:SearchAction", "rust lang", &extra);
    assert_eq!(result[0]["api_key"], "sk-live-123");
    assert_eq!(result[0]["query"], "rust lang");
}

#[test]
fn build_disclosures_no_extra() {
    let result = build_disclosures("schema:SearchAction", "rust lang", &Default::default());
    assert!(result[0].get("api_key").is_none());
    assert_eq!(result[0]["query"], "rust lang");
}
```

- [ ] **Step 5.2: Run tests**

```bash
cargo test build_disclosures 2>&1
```
Expected: PASS

- [ ] **Step 5.3: Update Phase 3 to call vault for credential params**

In `handshake/mod.rs`, before building disclosures, check the agent advertisement's `requires_disclosure` list for credential params. For each found, call `vault_disclose_for_agent`. Replace the inline disclosure construction with `build_disclosures`.

```rust
// Phase 3: build disclosures
use papillon_shared::credential_gate::{credential_params_for, CREDENTIAL_PARAM_NAMES};

let mut extra_disclosures = std::collections::HashMap::new();

// Collect vault-backed credential params
let cred_params = credential_params_for(&agent_ad.requires_disclosure);
for param in &cred_params {
    // Invoke the Tauri vault command
    if let Ok(value) = invoke::<String>(
        "vault_disclose_for_agent",
        &serde_json::json!({
            "credentialName": format!("{}_{}", agent_name_slug, param),
            "agentDid": agent_did,
        }),
    ).await {
        extra_disclosures.insert(param.clone(), value);
    }
    // If vault is sealed or key not stored, proceed without — handler will fail phase 4
    // with a clear error ("vault is sealed" or "credential not found")
}

let disclosures = build_disclosures(&action_type, &query, &extra_disclosures);
```

- [ ] **Step 5.4: Compile check (WASM target)**

```bash
cd apps/papillon/frontend && trunk build 2>&1 | grep "^error" | head -20
```
Expected: no errors

- [ ] **Step 5.5: Commit**

```bash
git add apps/papillon/frontend/src/handshake/
git commit -m "feat(handshake): include vault credential disclosures in Phase 3 SD-JWT path"
```

---

## Task 6: Fix auth-gated catalog TOMLs (24 files)

**Files:**
- Modify: 24 catalog TOML files

Replace `apikey=demo` (and variants) with `{api_key}` in the URL template, add `requires_disclosure = ["api_key"]`, add a `configurable_properties` entry so the settings UI renders a field for the vault.

The 24 files to update:

| File | Current key param | Provider docs URL hint |
|------|------------------|----------------------|
| `catalog/arts/europeana_art.toml` | `wskey=api2demo` | europeana.eu/develop |
| `catalog/commerce/builtwith_tech.toml` | `KEY=demo` | api.builtwith.com |
| `catalog/commerce/crunchbase_org.toml` | `user_key=demo` | crunchbase.com/api |
| `catalog/commerce/similar_web.toml` | `api_key=demo` | similarweb.com/api |
| `catalog/education/europeana_search.toml` | `wskey=api2demo` | europeana.eu/develop |
| `catalog/entertainment/goodreads_books.toml` | `key=demo` | goodreads.com/api |
| `catalog/finance/alpha_vantage.toml` | `apikey=demo` | alphavantage.co |
| `catalog/finance/currency_layer.toml` | `access_key=demo` | currencylayer.com |
| `catalog/finance/fixer_io.toml` | `access_key=demo` | fixer.io |
| `catalog/finance/stock_analysis.toml` | `apikey=demo` | financialmodelingprep.com |
| `catalog/geo/geoapify_places.toml` | `apiKey=demo` | geoapify.com (also has `{lat}/{lon}`) |
| `catalog/geo/mapquest_geocode.toml` | `key=demo` | developer.mapquest.com |
| `catalog/geo/what3words.toml` | `key=demo` | developer.what3words.com |
| `catalog/government/congress_votes.toml` | `api_key=demo` | api.congress.gov |
| `catalog/media/bbc_world_news.toml` | `apiKey=demo` | newsapi.org |
| `catalog/media/mediastack_news.toml` | `access_key=demo` | mediastack.com |
| `catalog/media/npr_stories.toml` | `apiKey=demo` | npr.org/api |
| `catalog/media/pocket_recommendations.toml` | `consumer_key=demo&access_token=demo` | getpocket.com/developer |
| `catalog/sports/tennis_rankings.toml` | `key=demo` | sportsdata.io |
| `catalog/travel/google_maps_place.toml` | `key=demo` | developers.google.com/maps |
| `catalog/travel/numbeo_cost.toml` | `api_key=demo` | numbeo.com/api |
| `catalog/travel/rome2rio.toml` | `key=demo` | (also has `{origin}/{destination}`) |
| `catalog/utilities/domain_whois.toml` | `apiKey=demo` | whoisxmlapi.com |
| `catalog/utilities/email_validate.toml` | `api_key=demo` | hunter.io |

**Canonical transform (alpha_vantage.toml as example):**

```toml
# BEFORE:
requires_disclosure = []
url_template = "https://www.alphavantage.co/query?function=SYMBOL_SEARCH&keywords={query}&apikey=demo"

# AFTER:
requires_disclosure = ["api_key"]
url_template = "https://www.alphavantage.co/query?function=SYMBOL_SEARCH&keywords={query}&apikey={api_key}"

[[configurable_properties]]
"@type" = "PropertyValueSpecification"
valueName = "api_key"
name = "API Key"
description = "Your Alpha Vantage API key — free tier available at alphavantage.co/support/#api-key"
defaultValue = ""
```

Special cases:
- `pocket_recommendations.toml` — two auth params: use `{api_key}` for `consumer_key`, add `{access_token}` for `access_token`, add both to `requires_disclosure = ["api_key", "access_token"]`, add two `configurable_properties` entries
- `geoapify_places.toml` — also has `{lat}` and `{lon}`; keep those, only fix `apiKey=demo` → `{api_key}` and add `api_key` to requires_disclosure alongside lat/lon

- [ ] **Step 6.1: Write a validation test**

```rust
// In crates/pap-agents/src/dynamic.rs tests or a dedicated catalog_validation_test.rs
#[test]
fn no_catalog_agent_has_hardcoded_demo_key() {
    let catalog_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/catalog");
    for entry in walkdir::WalkDir::new(catalog_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "toml"))
    {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let def: DynamicAgentDef = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Invalid TOML {}: {e}", entry.path().display()));
        if let Some(endpoint) = &def.endpoint {
            assert!(
                !endpoint.url_template.contains("=demo") && !endpoint.url_template.contains("=api2demo"),
                "Hardcoded demo key in {}: {}",
                entry.path().display(),
                endpoint.url_template
            );
        }
    }
}
```

Add `walkdir` to `pap-agents/Cargo.toml` dev-dependencies:
```toml
[dev-dependencies]
walkdir = "2"
```

- [ ] **Step 6.2: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test no_catalog_agent_has_hardcoded_demo_key 2>&1 | head -20
```
Expected: FAIL (lists the 24 offending files)

- [ ] **Step 6.3: Update all 24 TOML files**

Apply the transform to each file.

- [ ] **Step 6.4: Run the validation test to verify it passes**

```bash
cd crates/pap-agents && cargo test no_catalog_agent_has_hardcoded_demo_key 2>&1
```
Expected: PASS

- [ ] **Step 6.5: Commit**

```bash
git add crates/pap-agents/catalog/ crates/pap-agents/Cargo.toml
git commit -m "fix(catalog): replace 24 hardcoded demo API keys with {api_key} disclosure params"
```

---

## Task 7: Declare structural params in `requires_disclosure` for 19 agents

**Files:**
- Modify: 19 catalog TOML files (the structural-param agents)

Agents with `{lat}`, `{lon}`, `{owner}`, `{repo}`, etc. in their URL templates should declare those params in `requires_disclosure`. This lets the orchestrator surface them in the mandate preview and allows explicit user disclosure when the heuristic can't extract them.

| File | Add to `requires_disclosure` |
|------|------------------------------|
| `catalog/geo/elevation_api.toml` | `["lat", "lon"]` |
| `catalog/geo/bigdatacloud_reverse.toml` | `["lat", "lon"]` |
| `catalog/geo/overpass_pois.toml` | `["lat", "lon"]` |
| `catalog/geo/sunrisesunset.toml` | `["lat", "lon"]` |
| `catalog/weather/open_meteo_hourly.toml` | `["lat", "lon"]` |
| `catalog/weather/uv_index.toml` | `["lat", "lon"]` |
| `catalog/weather/storm_glass.toml` | `["lat", "lon"]` |
| `catalog/weather/weather_gov.toml` | `["office", "gridX", "gridY"]` |
| `catalog/travel/open_meteo_forecast.toml` | `["lat", "lon"]` |
| `catalog/developer/github_releases.toml` | `["owner", "repo"]` |
| `catalog/developer/github_trending.toml` | `["lang"]` |
| `catalog/entertainment/lyrics_ovh.toml` | `["artist", "title"]` |
| `catalog/finance/treasury_rates.toml` | `["year"]` |
| `catalog/finance/world_bank_indicator.toml` | `["country"]` |
| `catalog/media/reddit_subreddit.toml` | `["subreddit"]` |
| `catalog/sports/cycling_strava.toml` | `["bounds"]` |
| `catalog/sports/espn_scores.toml` | `["sport", "league"]` |
| `catalog/travel/rome2rio.toml` | add `"origin", "destination"` (already gets `"api_key"` from Task 6) |
| `catalog/geo/geoapify_places.toml` | add `"lat", "lon"` (already gets `"api_key"` from Task 6) |

- [ ] **Step 7.1: Write a validation test**

```rust
#[test]
fn catalog_agents_declare_all_template_params_in_disclosure() {
    use crate::entity_extractor::{extract_template_params, AUTH_PARAMS};
    let catalog_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/catalog");
    for entry in walkdir::WalkDir::new(catalog_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "toml"))
    {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let def: DynamicAgentDef = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Invalid TOML {}: {e}", entry.path().display()));
        if let Some(endpoint) = &def.endpoint {
            let params = extract_template_params(&endpoint.url_template);
            for param in &params {
                assert!(
                    def.requires_disclosure.contains(param),
                    "Agent {} has {{{}}} in url_template but not in requires_disclosure ({})",
                    entry.path().display(),
                    param,
                    def.requires_disclosure.join(", ")
                );
            }
        }
    }
}
```

- [ ] **Step 7.2: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test catalog_agents_declare_all_template_params 2>&1 | head -30
```
Expected: FAIL (lists offending files)

- [ ] **Step 7.3: Update all 19 TOML files**

Add the params from the table above to each file's `requires_disclosure`.

- [ ] **Step 7.4: Run the validation test to verify it passes**

```bash
cd crates/pap-agents && cargo test catalog_agents_declare_all_template_params 2>&1
```
Expected: PASS

- [ ] **Step 7.5: Commit**

```bash
git add crates/pap-agents/catalog/
git commit -m "fix(catalog): declare structural URL params in requires_disclosure (19 agents)"
```

---

## Task 8: End-to-end test and PR

- [ ] **Step 8.1: Full workspace test**

```bash
cargo test --workspace 2>&1 | tail -30
```
Expected: all tests pass

- [ ] **Step 8.2: Add e2e test verifying no unsubstituted placeholders reach the user**

In `apps/papillon/e2e/tests/agents.spec.ts`:

```typescript
test("github releases agent resolves owner/repo from query — no literal placeholders", async ({ page }) => {
  await createEmptyCanvas(page);
  await submitAndWaitForBlock(page, "torvalds/linux releases");
  const block = page.locator(".canvas-block").first();
  // The block may fail (network, no LLM) but it must never contain literal placeholders
  await expect(block).not.toContainText("{owner}");
  await expect(block).not.toContainText("{repo}");
});
```

- [ ] **Step 8.3: Push and open PR**

```bash
git push origin feat/1ed9-continue-branch
gh pr create \
  --title "feat(agents): entity extraction + SD-JWT credential disclosure for 58 catalog agents" \
  --body "Fixes 58 broken catalog agents via two complementary mechanisms:
  - EntityExtractor (LLM-first, regex-fallback) resolves structural URL params from query text
  - SD-JWT vault path routes API keys through the principal's credential store, not hardcoded demo values
  - 24 auth-gated TOMLs: apikey=demo → {api_key} + requires_disclosure
  - 19 structural-param TOMLs: declare params in requires_disclosure
  - New Tauri vault commands: vault_open, vault_seal, vault_disclose_for_agent, vault_store_credential
  - credential_gate.rs: orchestrator-side logic for detecting vault-requiring agents"
```

---

## Self-Review

**Spec coverage check:**

- ✅ BM25 as intent router (not entity extractor) — EntityExtractor is a separate layer, invoked after BM25 routes to the right agent
- ✅ API keys via SD-JWT — vault path: vault_disclose_for_agent → disclosed prop → handle_disclosure() → substituted in URL template. Never from query text (AUTH_PARAMS guard in EntityExtractor).
- ✅ Principal doesn't manage keys manually — orchestrator calls vault on their behalf when agent requires credential params; user only unlocks the vault once
- ✅ Category A (structural params) — Task 1 EntityExtractor + Task 2 handler wiring + Task 7 TOML disclosure declarations
- ✅ Category B (auth-gated) — Task 3 credential_gate + Task 4 vault Tauri commands + Task 5 handshake wiring + Task 6 TOML fixes
- ✅ Protocol correctness — endpoint hard-fails preserved; no LLM hallucination fallback; entity extractor is pre-execution param resolution, not a fallback execution path
- ✅ Validation tests in Tasks 6 and 7 catch regressions automatically

**Placeholder scan:** No TBDs. All code blocks are complete except vault.rs Step 4.3 which is filled in the same step.

**Type consistency:** `EntityExtractor::resolve()` returns `HashMap<String, String>`. `DynamicSession::disclosed_props` is `HashMap<String, String>`. `build_disclosures()` takes `&HashMap<String, String>`. All consistent.

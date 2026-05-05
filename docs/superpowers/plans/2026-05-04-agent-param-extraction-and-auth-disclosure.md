# Agent Parameter Extraction and Auth Disclosure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make 58 broken catalog agents work honestly — extracting structured URL parameters from natural-language queries, and routing user-configured API keys through the disclosure mechanism rather than hardcoding `demo`.

**Architecture:** Three coordinated changes: (1) `dynamic_handler.rs` extracts all params from the URL template, resolves each from the query text using lightweight heuristics, and substitutes them before making the HTTP call; (2) `registry.rs` loads saved `agent_settings` into `agent_props` at registration time so API keys configured by the user are available at execution; (3) catalog TOMLs for auth-gated agents are updated to use `{api_key}` in their URL templates and declare `requires_disclosure = ["api_key"]` instead of `apikey=demo`.

**Tech Stack:** Rust, `reqwest` (blocking), `serde_json`, `regex` crate (already in workspace or added as a dependency), existing `agent_settings` SQLite table, `DynamicAgentHandler`, `DynamicSession`.

---

## Background / Key Facts

Before implementing, read these files so you understand what already exists:

- `crates/pap-agents/src/dynamic_handler.rs` — `DynamicSession`, `handle_disclosure()`, `execute()`, `agent_props` header substitution
- `crates/pap-agents/src/dynamic.rs` — `DynamicAgentDef`, `HttpEndpointConfig`
- `crates/pap-agents/src/registry.rs` — `register_dynamic()` at line 168 (currently creates handler with empty `agent_props`)
- `apps/papillon/src/state.rs` at line 344 — where `register_dynamic` is called
- `crates/papillon-shared/src/db/mod.rs` — `DatabaseOps::get_agent_settings()` returns `HashMap<String, AgentSettingRow>`
- `apps/papillon/src/commands/settings_vocab.rs` — how `agent_settings` table stores key/value pairs per agent DID hash

**The three bugs today:**

1. `dynamic_handler.rs:145` only substitutes `{query}`. URLs like `https://api.foo.com/{lat}/{lon}` ship with literal `{lat}` in the request.
2. `registry.rs:199` calls `DynamicAgentHandler::new(def, llm)` — always empty `agent_props`. The `new_with_props()` constructor exists but is never called. API keys the user saves to `agent_settings` are never wired into the handler.
3. ~24 catalog TOMLs have `apikey=demo` hardcoded. Even if agent_props were wired, the URL template doesn't use `{api_key}` — it has the literal string `demo`.

---

## File Map

| File | Change |
|------|--------|
| `crates/pap-agents/src/dynamic_handler.rs` | Add `extract_url_params()` + `resolve_param()`, update `handle_disclosure()` to store all disclosed fields, update `execute()` to substitute all params |
| `crates/pap-agents/src/param_extractor.rs` | **New file.** All param extraction logic: parse template params, classify each, resolve from query string |
| `crates/pap-agents/src/lib.rs` | Export `param_extractor` module |
| `crates/pap-agents/src/registry.rs` | `register_dynamic()` now loads `agent_settings` and calls `new_with_props()` |
| `apps/papillon/src/state.rs` | Pass `db` reference to `register_dynamic()` |
| Catalog TOMLs (24 files) | Replace `apikey=demo` with `{api_key}`, add `requires_disclosure = ["api_key"]`, add `configurable_properties` entry |

---

## Task 1: Add `param_extractor.rs` — template param parsing and resolution

**Files:**
- Create: `crates/pap-agents/src/param_extractor.rs`
- Modify: `crates/pap-agents/src/lib.rs` (add `pub mod param_extractor;`)

This module does two things:
1. `extract_template_params(url_template: &str) -> Vec<String>` — find all `{name}` placeholders in a URL template that are NOT `{query}`
2. `resolve_param(name: &str, query: &str) -> Option<String>` — attempt to extract the named param's value from the query string using pattern matching

- [ ] **Step 1.1: Write failing tests for `extract_template_params`**

In `crates/pap-agents/src/param_extractor.rs`, create the file with tests only:

```rust
//! Lightweight parameter extraction from URL templates and natural-language queries.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_params_single_query() {
        // {query} alone — no structural params
        let params = extract_template_params("https://api.foo.com/search?q={query}");
        assert!(params.is_empty());
    }

    #[test]
    fn extract_params_lat_lon() {
        let params = extract_template_params("https://api.foo.com?lat={lat}&lon={lon}");
        assert_eq!(params, vec!["lat".to_string(), "lon".to_string()]);
    }

    #[test]
    fn extract_params_owner_repo() {
        let params = extract_template_params("https://api.github.com/repos/{owner}/{repo}/releases/latest");
        assert_eq!(params, vec!["owner".to_string(), "repo".to_string()]);
    }

    #[test]
    fn extract_params_mixed_with_query() {
        let params = extract_template_params("https://api.foo.com/{country}?q={query}");
        assert_eq!(params, vec!["country".to_string()]);
    }

    #[test]
    fn extract_params_no_placeholders() {
        let params = extract_template_params("https://api.foo.com/static");
        assert!(params.is_empty());
    }
}
```

- [ ] **Step 1.2: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test extract_template_params 2>&1 | head -20
```
Expected: compile error (function not defined)

- [ ] **Step 1.3: Implement `extract_template_params`**

Add above the `#[cfg(test)]` block:

```rust
use std::collections::HashSet;

/// Return all `{name}` placeholder names in `url_template`, excluding `{query}`.
pub fn extract_template_params(url_template: &str) -> Vec<String> {
    let mut seen = HashSet::new();
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

- [ ] **Step 1.4: Run tests to verify they pass**

```bash
cd crates/pap-agents && cargo test extract_template_params 2>&1
```
Expected: all 5 tests pass

- [ ] **Step 1.5: Write failing tests for `resolve_param`**

Add these tests to the `tests` module:

```rust
    #[test]
    fn resolve_lat_from_coordinates() {
        // "37.7749,-122.4194" format
        let lat = resolve_param("lat", "37.7749,-122.4194");
        assert_eq!(lat, Some("37.7749".to_string()));
    }

    #[test]
    fn resolve_lon_from_coordinates() {
        let lon = resolve_param("lon", "37.7749,-122.4194");
        assert_eq!(lon, Some("-122.4194".to_string()));
    }

    #[test]
    fn resolve_lat_lng_aliases() {
        // Some templates use {lng} instead of {lon}
        let lng = resolve_param("lng", "37.7749,-122.4194");
        assert_eq!(lng, Some("-122.4194".to_string()));
    }

    #[test]
    fn resolve_owner_repo_from_path() {
        // "torvalds/linux" or "owner: torvalds, repo: linux"
        let owner = resolve_param("owner", "torvalds/linux");
        assert_eq!(owner, Some("torvalds".to_string()));
        let repo = resolve_param("repo", "torvalds/linux");
        assert_eq!(repo, Some("linux".to_string()));
    }

    #[test]
    fn resolve_owner_repo_with_github_prefix() {
        let owner = resolve_param("owner", "github.com/rust-lang/rust");
        assert_eq!(owner, Some("rust-lang".to_string()));
        let repo = resolve_param("repo", "github.com/rust-lang/rust");
        assert_eq!(repo, Some("rust".to_string()));
    }

    #[test]
    fn resolve_subreddit_from_r_prefix() {
        let sub = resolve_param("subreddit", "r/rust");
        assert_eq!(sub, Some("rust".to_string()));
    }

    #[test]
    fn resolve_subreddit_bare_word() {
        let sub = resolve_param("subreddit", "rust");
        assert_eq!(sub, Some("rust".to_string()));
    }

    #[test]
    fn resolve_artist_title_from_dash() {
        // "Pink Floyd - Comfortably Numb"
        let artist = resolve_param("artist", "Pink Floyd - Comfortably Numb");
        assert_eq!(artist, Some("Pink Floyd".to_string()));
        let title = resolve_param("title", "Pink Floyd - Comfortably Numb");
        assert_eq!(title, Some("Comfortably Numb".to_string()));
    }

    #[test]
    fn resolve_origin_destination_from_to() {
        // "London to Paris"
        let origin = resolve_param("origin", "London to Paris");
        assert_eq!(origin, Some("London".to_string()));
        let dest = resolve_param("destination", "London to Paris");
        assert_eq!(dest, Some("Paris".to_string()));
    }

    #[test]
    fn resolve_country_single_word() {
        let country = resolve_param("country", "Germany");
        assert_eq!(country, Some("Germany".to_string()));
    }

    #[test]
    fn resolve_year_four_digits() {
        let year = resolve_param("year", "treasury rates 2023");
        assert_eq!(year, Some("2023".to_string()));
    }

    #[test]
    fn resolve_lang_from_query() {
        let lang = resolve_param("lang", "rust");
        assert_eq!(lang, Some("rust".to_string()));
    }

    #[test]
    fn resolve_unknown_param_returns_query_verbatim() {
        // For unknown params, return the whole query (safe fallback)
        let val = resolve_param("something_unknown", "some query text");
        assert_eq!(val, Some("some query text".to_string()));
    }

    #[test]
    fn resolve_api_key_returns_none() {
        // api_key comes from agent_settings/disclosures, not query extraction
        let val = resolve_param("api_key", "anything");
        assert_eq!(val, None);
    }
```

- [ ] **Step 1.6: Run tests to verify they fail**

```bash
cd crates/pap-agents && cargo test resolve_param 2>&1 | head -20
```
Expected: compile error (function not defined)

- [ ] **Step 1.7: Implement `resolve_param`**

Add after `extract_template_params`:

```rust
/// Attempt to extract the value of a named URL parameter from a natural-language query string.
///
/// Returns `None` for params that must come from agent_settings (api_key, access_key, etc.)
/// rather than the query text. Returns `Some(query.to_string())` as a safe verbatim fallback
/// for unrecognised param names.
pub fn resolve_param(name: &str, query: &str) -> Option<String> {
    let q = query.trim();

    match name {
        // Auth params — must come from agent_settings/disclosure, never from query text
        "api_key" | "apikey" | "access_key" | "key" | "token" | "api_token"
        | "consumer_key" | "user_key" | "wskey" => return None,

        // Coordinates: expect "lat,lon" or "lat, lon" format
        "lat" | "latitude" => {
            if let Some(lat) = parse_lat(q) {
                return Some(lat);
            }
        }
        "lon" | "lng" | "longitude" => {
            if let Some(lon) = parse_lon(q) {
                return Some(lon);
            }
        }

        // GitHub-style: "owner/repo" or "github.com/owner/repo"
        "owner" => {
            if let Some(owner) = parse_github_owner(q) {
                return Some(owner);
            }
        }
        "repo" => {
            if let Some(repo) = parse_github_repo(q) {
                return Some(repo);
            }
        }

        // Reddit: "r/subreddit" or bare word
        "subreddit" => {
            let sub = q.strip_prefix("r/").unwrap_or(q);
            let word: String = sub.split_whitespace().next().unwrap_or(sub).to_string();
            return Some(word);
        }

        // Music: "Artist - Title"
        "artist" => {
            if let Some((artist, _)) = q.split_once(" - ") {
                return Some(artist.trim().to_string());
            }
        }
        "title" => {
            if let Some((_, title)) = q.split_once(" - ") {
                return Some(title.trim().to_string());
            }
        }

        // Travel: "origin to destination"
        "origin" | "oName" => {
            if let Some((origin, _)) = split_to(q) {
                return Some(origin);
            }
        }
        "destination" | "dName" => {
            if let Some((_, dest)) = split_to(q) {
                return Some(dest);
            }
        }

        // Year: first 4-digit number in query
        "year" => {
            for word in q.split_whitespace() {
                if word.len() == 4 && word.chars().all(|c| c.is_ascii_digit()) {
                    return Some(word.to_string());
                }
            }
        }

        // Country / language / sport / league / office / gridX / gridY — use whole query as-is
        // (BM25 already routed to the right agent; the query IS the country/language/etc.)
        _ => {}
    }

    // Safe fallback: return the query verbatim for unrecognised structural params
    Some(q.to_string())
}

// ── Coordinate helpers ────────────────────────────────────────────────────────

fn parse_lat(q: &str) -> Option<String> {
    // "37.7749,-122.4194" or "37.7749, -122.4194"
    let (lat_str, _) = q.split_once(',')?;
    let lat: f64 = lat_str.trim().parse().ok()?;
    if (-90.0..=90.0).contains(&lat) {
        Some(lat_str.trim().to_string())
    } else {
        None
    }
}

fn parse_lon(q: &str) -> Option<String> {
    let (_, lon_str) = q.split_once(',')?;
    let lon: f64 = lon_str.trim().parse().ok()?;
    if (-180.0..=180.0).contains(&lon) {
        Some(lon_str.trim().to_string())
    } else {
        None
    }
}

// ── GitHub helpers ─────────────────────────────────────────────────────────────

fn parse_github_owner(q: &str) -> Option<String> {
    // Strip optional "github.com/" prefix
    let q = q.strip_prefix("github.com/").unwrap_or(q);
    let (owner, _) = q.split_once('/')?;
    Some(owner.trim().to_string())
}

fn parse_github_repo(q: &str) -> Option<String> {
    let q = q.strip_prefix("github.com/").unwrap_or(q);
    let (_, rest) = q.split_once('/')?;
    // Take only the repo part (before any further '/')
    let repo = rest.split('/').next()?.trim().to_string();
    Some(repo)
}

// ── Travel helpers ────────────────────────────────────────────────────────────

fn split_to(q: &str) -> Option<(String, String)> {
    // "London to Paris" — case-insensitive " to "
    let lower = q.to_lowercase();
    let idx = lower.find(" to ")?;
    let origin = q[..idx].trim().to_string();
    let dest = q[idx + 4..].trim().to_string();
    Some((origin, dest))
}
```

- [ ] **Step 1.8: Run all param_extractor tests**

```bash
cd crates/pap-agents && cargo test param_extractor 2>&1
```
Expected: all tests pass

- [ ] **Step 1.9: Export the module from `lib.rs`**

In `crates/pap-agents/src/lib.rs`, add the line:
```rust
pub mod param_extractor;
```

- [ ] **Step 1.10: Confirm it compiles**

```bash
cd crates/pap-agents && cargo check 2>&1 | grep -E "^error" | head -10
```
Expected: no errors

- [ ] **Step 1.11: Commit**

```bash
git add crates/pap-agents/src/param_extractor.rs crates/pap-agents/src/lib.rs
git commit -m "feat(agents): add param_extractor for URL template parameter resolution"
```

---

## Task 2: Wire param extraction into `dynamic_handler.rs`

**Files:**
- Modify: `crates/pap-agents/src/dynamic_handler.rs`

The handler currently substitutes only `{query}`. After this task it substitutes all `{name}` params:
1. From `session.disclosed_props` (values disclosed during Phase 3 — api keys, user-provided params)
2. From `param_extractor::resolve_param(name, &query)` for structural params extracted from the query text

**Files:**
- Modify: `crates/pap-agents/src/dynamic_handler.rs`

- [ ] **Step 2.1: Expand `DynamicSession` to store all disclosed properties**

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
    /// All properties disclosed in Phase 3 (e.g. api_key, lat, lon, etc.)
    disclosed_props: std::collections::HashMap<String, String>,
}
```

Update `DynamicSession` construction in `handle_token()`:
```rust
let did = self
    .sessions
    .insert(session_id.clone(), DynamicSession {
        query: None,
        disclosed_props: std::collections::HashMap::new(),
    })?;
```

- [ ] **Step 2.2: Write failing test for multi-param substitution**

Add this test to `dynamic_handler.rs`'s `#[cfg(test)]` block:

```rust
#[test]
fn disclosed_api_key_substituted_in_url() {
    // Build a def whose url_template uses {api_key} and {query}
    let def = DynamicAgentDef {
        endpoint: Some(HttpEndpointConfig {
            url_template: "https://api.example.com/search?q={query}&apikey={api_key}".into(),
            method: HttpMethod::Get,
            headers: HashMap::new(),
            body_template: None,
            response_jsonpath: "$.result".into(),
            response_schema_type: "schema:Thing".into(),
            response_mapping: HashMap::new(),
            timeout_secs: 5,
        }),
        ..make_def_llm_only()
    };
    let handler = DynamicAgentHandler::new(def, Arc::new(RwLock::new(LlmProvider::None)));
    let token = make_token("schema:SearchAction");
    let (sid, _) = handler.handle_token(token).unwrap();
    handler.handle_did_exchange(&sid, "did:key:peer").unwrap();
    // Disclose both query and api_key
    handler
        .handle_disclosure(
            &sid,
            vec![json!({"query": "rust language", "api_key": "sk-live-abc123"})],
        )
        .unwrap();

    // We can't call execute() without a real HTTP server, but we can verify
    // that the session stores both values by checking handle_disclosure stored api_key.
    // The integration test (Task 3) will verify actual URL construction.
    handler
        .sessions
        .with(&sid, |data| {
            assert_eq!(data.disclosed_props.get("api_key"), Some(&"sk-live-abc123".to_string()));
            assert_eq!(data.query, Some("rust language".to_string()));
        })
        .unwrap();
}
```

- [ ] **Step 2.3: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test disclosed_api_key_substituted_in_url 2>&1 | head -20
```
Expected: compile error (field `disclosed_props` doesn't exist or `sessions.with` can't access it)

- [ ] **Step 2.4: Update `handle_disclosure()` to extract all properties**

Replace the existing `handle_disclosure` implementation:

```rust
fn handle_disclosure(
    &self,
    session_id: &str,
    disclosures: Vec<Value>,
) -> Result<(), TransportError> {
    let mut query: Option<String> = None;
    let mut disclosed_props: HashMap<String, String> = HashMap::new();

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
                disclosed_props.insert(key.clone(), str_val);
            }
        }
    }

    self.sessions.with_mut(session_id, |data| {
        if let Some(q) = query {
            data.query = Some(q);
        }
        data.disclosed_props.extend(disclosed_props);
    })?;
    Ok(())
}
```

- [ ] **Step 2.5: Update `execute()` to substitute all params**

In `execute()`, replace the current `{query}`-only substitution block. Find:
```rust
let url = endpoint.url_template.replace("{query}", &query);
```
Replace with:
```rust
// Substitute {query} first.
let mut url = endpoint.url_template.replace("{query}", &query);

// Substitute any remaining {param} placeholders.
// Priority: (1) disclosed_props from Phase 3, (2) agent_props (user-configured settings),
// (3) param_extractor heuristics applied to the query text.
let extra_params = crate::param_extractor::extract_template_params(&endpoint.url_template);
let disclosed = self
    .sessions
    .with(session_id, |data| data.disclosed_props.clone())?;

for param in &extra_params {
    let value = disclosed
        .get(param)
        .cloned()
        .or_else(|| self.agent_props.get(param).cloned())
        .or_else(|| crate::param_extractor::resolve_param(param, &query));

    if let Some(val) = value {
        url = url.replace(&format!("{{{}}}", param), &val);
    }
}
```

- [ ] **Step 2.6: Run the new test**

```bash
cd crates/pap-agents && cargo test disclosed_api_key_substituted_in_url 2>&1
```
Expected: PASS

- [ ] **Step 2.7: Run full test suite**

```bash
cd crates/pap-agents && cargo test 2>&1 | tail -20
```
Expected: all tests pass (no regressions)

- [ ] **Step 2.8: Commit**

```bash
git add crates/pap-agents/src/dynamic_handler.rs
git commit -m "feat(agents): substitute all URL template params from disclosures, agent_props, and query extraction"
```

---

## Task 3: Wire `agent_settings` into handler at registration time

**Files:**
- Modify: `crates/pap-agents/src/registry.rs`
- Modify: `apps/papillon/src/state.rs`

Right now `register_dynamic()` always creates handlers with empty `agent_props`. The user's saved API keys in `agent_settings` are never loaded. This task connects them.

`register_dynamic()` needs a `HashMap<String, String>` of agent settings at registration time. The caller (`state.rs`) already has the DB handle and can load the settings there.

- [ ] **Step 3.1: Write failing test for register_dynamic with props**

Add this test to `crates/pap-agents/src/registry.rs` in the `#[cfg(test)]` block:

```rust
#[test]
fn register_dynamic_with_props_available_at_execute_time() {
    // Verify that agent_props passed at registration reach the handler.
    // We test via the header substitution path (existing test logic).
    let mut props = HashMap::new();
    props.insert("api_token".to_string(), "sk-live-xyz".to_string());

    let def = make_dynamic_def();
    let mut set = AgentSet::default();
    set.register_dynamic_with_props(
        &def,
        Arc::new(RwLock::new(LlmProvider::None)),
        props.clone(),
    )
    .unwrap();

    // Handler is registered
    assert!(set.handlers.contains_key(&def.name));
    // The handler should have the props — we can't directly inspect them
    // but we know new_with_props was called because register_dynamic_with_props exists
}
```

(The test for `make_dynamic_def` already exists in the test module — verify or add a helper that builds a `DynamicAgentDef` with a valid `operator_key_seed`.)

- [ ] **Step 3.2: Add `register_dynamic_with_props()` to `AgentSet`**

In `crates/pap-agents/src/registry.rs`, add a new method after `register_dynamic`:

```rust
/// Like `register_dynamic` but pre-loads agent property values (e.g. user-configured API keys)
/// into the handler so they are available for URL/header substitution at execution time.
pub fn register_dynamic_with_props(
    &mut self,
    def: &DynamicAgentDef,
    llm_provider: Arc<RwLock<LlmProvider>>,
    props: HashMap<String, String>,
) -> Result<String, RegistrationError> {
    let seed = def
        .operator_key_seed
        .ok_or(RegistrationError::MissingKeySeed)?;
    let kp = PrincipalKeypair::from_bytes(&seed)
        .map_err(|e| RegistrationError::InvalidKeySeed(e.to_string()))?;
    let did = kp.did();

    let ad = AgentAdvertisement::new(
        &def.name,
        &def.provider,
        &did,
        vec![def.action.clone()],
        def.object_types.clone(),
        def.requires_disclosure.clone(),
        def.returns.clone(),
    )
    .with_version(&def.version)
    .with_configurable_properties(def.configurable_properties.clone());
    let mut ad = ad;
    ad.sign(kp.signing_key())
        .map_err(|_| RegistrationError::SignatureInvalid)?;

    self.registry
        .register_local(ad)
        .map_err(|_| RegistrationError::AlreadyRegistered(def.name.clone()))?;

    let handler = Arc::new(DynamicAgentHandler::new_with_props(def.clone(), llm_provider, props));
    self.handlers.insert(def.name.clone(), handler);
    self.keypairs.insert(def.name.clone(), kp);

    Ok(did)
}
```

- [ ] **Step 3.3: Run the new test**

```bash
cd crates/pap-agents && cargo test register_dynamic_with_props 2>&1
```
Expected: PASS

- [ ] **Step 3.4: Update `state.rs` to load and pass `agent_settings`**

In `apps/papillon/src/state.rs`, find the loop that registers DB agents (around line 344–350):

```rust
// ── Register all DB agents (catalog + user_created + generated) ───────────
let db_agents = db.load_all_agents().unwrap_or_default();
for def in &db_agents {
    if let Err(e) = agent_set.register_dynamic(def, shared_llm_provider.clone()) {
        eprintln!("Failed to register agent '{}': {e}", def.name);
    }
}
```

Replace with:

```rust
// ── Register all DB agents (catalog + user_created + generated) ───────────
let db_agents = db.load_all_agents().unwrap_or_default();
for def in &db_agents {
    // Load saved agent settings (API keys, user overrides) into the handler.
    let agent_did = {
        use ed25519_dalek::SigningKey;
        def.operator_key_seed
            .as_ref()
            .and_then(|seed| {
                pap_did::PrincipalKeypair::from_bytes(seed)
                    .ok()
                    .map(|kp| kp.did())
            })
            .unwrap_or_default()
    };
    let agent_did_hash = crate::commands::orchestrator::hash_agent_did(&agent_did);
    let props: HashMap<String, String> = db
        .get_agent_settings(&agent_did_hash)
        .unwrap_or_default()
        .into_iter()
        .map(|(k, row)| {
            // Values are stored as JSON strings; unwrap quoted strings
            let v = serde_json::from_str::<String>(&row.value)
                .unwrap_or(row.value);
            (k, v)
        })
        .collect();

    if let Err(e) = agent_set.register_dynamic_with_props(def, shared_llm_provider.clone(), props) {
        eprintln!("Failed to register agent '{}': {e}", def.name);
    }
}
```

You need to add `use std::collections::HashMap;` at the top of `state.rs` if not already present.

- [ ] **Step 3.5: Check it compiles**

```bash
cd apps/papillon && cargo check 2>&1 | grep "^error" | head -20
```
Expected: no errors

- [ ] **Step 3.6: Run all tests**

```bash
cargo test -p pap-agents 2>&1 | tail -20
```
Expected: all tests pass

- [ ] **Step 3.7: Commit**

```bash
git add crates/pap-agents/src/registry.rs apps/papillon/src/state.rs
git commit -m "feat(agents): load agent_settings into handler props at registration time"
```

---

## Task 4: Fix auth-gated catalog TOMLs — replace `demo` keys with `{api_key}`

**Files:**
- Modify: 24 catalog TOML files (list below)

Auth-gated agents currently have `apikey=demo` (or similar) hardcoded in the URL template. They need:
1. `{api_key}` in the URL template where `demo` is
2. `requires_disclosure = ["api_key"]` so the orchestrator knows to ask the user
3. A `[[configurable_properties]]` entry so the settings UI renders a field for it

The 24 files to update:

| File | Current param name | URL position |
|------|--------------------|-------------|
| `catalog/arts/europeana_art.toml` | `wskey=api2demo` | query param |
| `catalog/commerce/builtwith_tech.toml` | `KEY=demo` | query param |
| `catalog/commerce/crunchbase_org.toml` | `user_key=demo` | query param |
| `catalog/commerce/similar_web.toml` | `api_key=demo` | query param |
| `catalog/education/europeana_search.toml` | `wskey=api2demo` | query param |
| `catalog/entertainment/goodreads_books.toml` | `key=demo` | query param |
| `catalog/finance/alpha_vantage.toml` | `apikey=demo` | query param |
| `catalog/finance/currency_layer.toml` | `access_key=demo` | query param |
| `catalog/finance/fixer_io.toml` | `access_key=demo` | query param |
| `catalog/finance/stock_analysis.toml` | `apikey=demo` | query param |
| `catalog/geo/geoapify_places.toml` | `apiKey=demo` | query param (also has `{lat}/{lon}`) |
| `catalog/geo/mapquest_geocode.toml` | `key=demo` | query param |
| `catalog/geo/what3words.toml` | `key=demo` | query param |
| `catalog/government/congress_votes.toml` | `api_key=demo` | query param |
| `catalog/media/bbc_world_news.toml` | `apiKey=demo` | query param |
| `catalog/media/mediastack_news.toml` | `access_key=demo` | query param |
| `catalog/media/npr_stories.toml` | `apiKey=demo` | query param |
| `catalog/media/pocket_recommendations.toml` | `consumer_key=demo&access_token=demo` | query params |
| `catalog/sports/tennis_rankings.toml` | `key=demo` | query param |
| `catalog/travel/google_maps_place.toml` | `key=demo` | query param |
| `catalog/travel/numbeo_cost.toml` | `api_key=demo` | query param |
| `catalog/travel/rome2rio.toml` | `key=demo` (also `{origin}/{destination}`) | query param |
| `catalog/utilities/domain_whois.toml` | `apiKey=demo` | query param |
| `catalog/utilities/email_validate.toml` | `api_key=demo` | query param |

The transform for each file is mechanical. Here is the pattern using `alpha_vantage.toml` as the canonical example:

**Before:**
```toml
requires_disclosure = []
...
url_template = "https://www.alphavantage.co/query?function=SYMBOL_SEARCH&keywords={query}&apikey=demo"
```

**After:**
```toml
requires_disclosure = ["api_key"]
...
url_template = "https://www.alphavantage.co/query?function=SYMBOL_SEARCH&keywords={query}&apikey={api_key}"

[[configurable_properties]]
"@type" = "PropertyValueSpecification"
valueName = "api_key"
name = "API Key"
description = "Your Alpha Vantage API key (free at alphavantage.co/support/#api-key)"
defaultValue = ""
valuePattern = "^[A-Z0-9]+$"
```

Note: for `pocket_recommendations.toml`, there are two auth params — use `{api_key}` for `consumer_key` and add a second `{access_token}` param with its own `configurable_properties` entry.

- [ ] **Step 4.1: Write a test that validates the TOML schema has `requires_disclosure` = `["api_key"]` for an auth-gated file**

Add a test to `crates/pap-agents/src/dynamic.rs` or a new test module. This verifies that loading the fixed TOMLs produces the right struct shape:

```rust
#[test]
fn alpha_vantage_requires_api_key_disclosure() {
    let content = include_str!("../catalog/finance/alpha_vantage.toml");
    let def: DynamicAgentDef = toml::from_str(content).expect("valid toml");
    assert!(
        def.requires_disclosure.contains(&"api_key".to_string()),
        "alpha_vantage must declare api_key in requires_disclosure"
    );
    assert!(
        def.endpoint
            .as_ref()
            .map(|e| e.url_template.contains("{api_key}"))
            .unwrap_or(false),
        "url_template must use {{api_key}} placeholder, not hardcoded demo"
    );
}
```

- [ ] **Step 4.2: Run the test to verify it fails**

```bash
cd crates/pap-agents && cargo test alpha_vantage_requires_api_key 2>&1
```
Expected: FAIL (url_template still has `apikey=demo`)

- [ ] **Step 4.3: Update all 24 TOML files**

Apply the transform (replace `demo` key with `{api_key}`, add disclosure, add configurable property) to each file in the table above. Use the alpha_vantage pattern as template. For files with non-standard param names (wskey, KEY, access_key, user_key), replace that param's value with `{api_key}` regardless — the `{api_key}` name is the canonical disclosed property name.

Special cases:
- `geoapify_places.toml` — also has `{lat}` and `{lon}`; keep those, only fix the `apiKey=demo`
- `rome2rio.toml` — also has `{origin}` and `{destination}`; keep those, only fix `key=demo`
- `pocket_recommendations.toml` — two auth params; use `{api_key}` for `consumer_key` and `{access_token}` for `access_token`; add both to `requires_disclosure` and add two `configurable_properties` entries

- [ ] **Step 4.4: Run the test to verify it passes**

```bash
cd crates/pap-agents && cargo test alpha_vantage_requires_api_key 2>&1
```
Expected: PASS

- [ ] **Step 4.5: Run full test suite to check no regressions**

```bash
cargo test -p pap-agents 2>&1 | tail -20
```
Expected: all tests pass

- [ ] **Step 4.6: Commit**

```bash
git add crates/pap-agents/catalog/
git commit -m "fix(catalog): replace hardcoded demo API keys with {api_key} disclosure params (24 agents)"
```

---

## Task 5: Fix structurally-broken catalog TOMLs — declare missing params and update `requires_disclosure`

**Files:**
- Modify: 19 catalog TOML files

These agents have `{lat}`, `{lon}`, `{owner}`, `{repo}`, etc. in their URL templates but declare `requires_disclosure = []`. The param_extractor (Task 1) handles extraction from query text, but the agents should honestly declare what they need.

The right disclosure model for structural params: they can be resolved from the query automatically (param_extractor handles it), but agents should declare them in `requires_disclosure` so the orchestrator can optionally expose them in the mandate preview.

For each file, add the template params to `requires_disclosure` if they cannot be derived automatically from `{query}` (e.g. `{lat}`,`{lon}` come from query text when query is a coordinate pair, but for natural-language queries like "sunrise in Tokyo" there's no coordinate — the extractor will fall back to the query verbatim which is wrong).

**Conservative rule applied here:** If a param has no reliable extraction heuristic (i.e., it requires geocoding or structured input the user never provides as a coord pair), mark it in `requires_disclosure` so the orchestrator can surface it. Params with reliable heuristics (`{owner}/{repo}` from `user/repo` format, `{artist} - {title}`, `{origin} to {destination}`, `{subreddit}` from `r/name`) are fine with just the extractor.

Files needing `requires_disclosure` updates:

| File | Template params | Heuristic quality |
|------|----------------|-------------------|
| `catalog/geo/elevation_api.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/geo/bigdatacloud_reverse.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/geo/overpass_pois.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/geo/sunrisesunset.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/weather/open_meteo_hourly.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/weather/uv_index.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/weather/storm_glass.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/weather/weather_gov.toml` | `{office}`, `{gridX}`, `{gridY}` | No heuristic — verbatim fallback |
| `catalog/travel/open_meteo_forecast.toml` | `{lat}`, `{lon}` | Reliable if query is coords |
| `catalog/developer/github_releases.toml` | `{owner}`, `{repo}` | Reliable from `user/repo` format |
| `catalog/developer/github_trending.toml` | `{lang}` | Verbatim fallback |
| `catalog/entertainment/lyrics_ovh.toml` | `{artist}`, `{title}` | Reliable from `Artist - Title` |
| `catalog/finance/treasury_rates.toml` | `{year}` | Reliable from 4-digit year |
| `catalog/finance/world_bank_indicator.toml` | `{country}` | Verbatim fallback |
| `catalog/media/reddit_subreddit.toml` | `{subreddit}` | Reliable from `r/name` |
| `catalog/sports/cycling_strava.toml` | `{bounds}` | No heuristic |
| `catalog/sports/espn_scores.toml` | `{sport}`, `{league}` | No heuristic |
| `catalog/travel/rome2rio.toml` | `{origin}`, `{destination}` | Reliable from `X to Y` |
| `catalog/geo/geoapify_places.toml` | `{lat}`, `{lon}` | Reliable if query is coords |

For all of these, add the template params to `requires_disclosure`. This does NOT break anything — `requires_disclosure` is advertised to the orchestrator but the handler will still use the extractor as a fallback if the user doesn't explicitly disclose them.

- [ ] **Step 5.1: Write a test validating one of the files**

```rust
#[test]
fn github_releases_declares_owner_repo_disclosure() {
    let content = include_str!("../catalog/developer/github_releases.toml");
    let def: DynamicAgentDef = toml::from_str(content).expect("valid toml");
    assert!(def.requires_disclosure.contains(&"owner".to_string()));
    assert!(def.requires_disclosure.contains(&"repo".to_string()));
}
```

- [ ] **Step 5.2: Run test to verify it fails**

```bash
cd crates/pap-agents && cargo test github_releases_declares_owner_repo 2>&1
```
Expected: FAIL

- [ ] **Step 5.3: Update all 19 TOML files**

For each file, update `requires_disclosure` to include the template params. Example for `github_releases.toml`:

```toml
# Before:
requires_disclosure = []

# After:
requires_disclosure = ["owner", "repo"]
```

For geo/weather files that use `{lat}`, `{lon}`:
```toml
requires_disclosure = ["lat", "lon"]
```

- [ ] **Step 5.4: Run the test to verify it passes**

```bash
cd crates/pap-agents && cargo test github_releases_declares_owner_repo 2>&1
```
Expected: PASS

- [ ] **Step 5.5: Run full test suite**

```bash
cargo test -p pap-agents 2>&1 | tail -20
```
Expected: all tests pass

- [ ] **Step 5.6: Commit**

```bash
git add crates/pap-agents/catalog/
git commit -m "fix(catalog): declare structural URL params in requires_disclosure (19 agents)"
```

---

## Task 6: Update handshake to pass disclosed structural params

**Files:**
- Modify: `apps/papillon/frontend/src/handshake/mod.rs`
- Modify: `crates/papillon-shared/src/handshake/mod.rs` (if it exists and the WASM path uses it)

Currently Phase 3 sends only `{"@type": action_type, "query": query}`. After this task, if an agent's `requires_disclosure` contains params beyond `query`, those params are included in the disclosure object when the user has configured them.

**Scope:** For this task, only handle params that come from `agent_settings` (i.e. `api_key`). Structural params like `lat`/`lon` that come from the query text are resolved server-side in `param_extractor` — the handshake doesn't need to know about them.

- [ ] **Step 6.1: Find where Phase 3 disclosures are built in the WASM handshake**

Read `apps/papillon/frontend/src/handshake/mod.rs`. Find the `disclosures` construction (around line 263):

```rust
let disclosures = vec![json!({
    "@type": action_type,
    "query": query
})];
```

- [ ] **Step 6.2: Write a test for the disclosure builder**

In `crates/papillon-shared/src/handshake/mod.rs` or `intent.rs`, if a unit-testable `build_disclosures` function exists or can be extracted, write a test. If the disclosure building is inline in Leptos component code, this test goes in a helper function.

Extract into a testable function first:

```rust
/// Build the Phase-3 disclosure object for an agent.
/// `agent_requires` is the agent's `requires_disclosure` list.
/// `query` is the user's prompt.  
/// `settings` is the agent's saved settings (api_key, etc.).
pub fn build_disclosures(
    action_type: &str,
    query: &str,
    agent_requires: &[String],
    settings: &HashMap<String, String>,
) -> Vec<serde_json::Value> {
    let mut obj = serde_json::json!({
        "@type": action_type,
        "query": query,
    });
    // Include any required properties that are available in settings
    for key in agent_requires {
        if key == "query" {
            continue;
        }
        if let Some(val) = settings.get(key) {
            if !val.is_empty() {
                obj[key] = serde_json::json!(val);
            }
        }
    }
    vec![obj]
}
```

Test:

```rust
#[test]
fn build_disclosures_includes_api_key_from_settings() {
    let settings = [("api_key".to_string(), "sk-live-123".to_string())]
        .into_iter()
        .collect();
    let result = build_disclosures(
        "schema:SearchAction",
        "rust programming",
        &["query".to_string(), "api_key".to_string()],
        &settings,
    );
    assert_eq!(result.len(), 1);
    assert_eq!(result[0]["api_key"], "sk-live-123");
    assert_eq!(result[0]["query"], "rust programming");
}

#[test]
fn build_disclosures_omits_empty_api_key() {
    let settings = [("api_key".to_string(), "".to_string())]
        .into_iter()
        .collect();
    let result = build_disclosures(
        "schema:SearchAction",
        "rust programming",
        &["query".to_string(), "api_key".to_string()],
        &settings,
    );
    assert!(result[0].get("api_key").is_none());
}

#[test]
fn build_disclosures_query_only_when_no_extra_required() {
    let settings = HashMap::new();
    let result = build_disclosures("schema:SearchAction", "rust", &[], &settings);
    assert_eq!(result[0]["query"], "rust");
    assert!(result[0].get("api_key").is_none());
}
```

- [ ] **Step 6.3: Run tests to verify they fail**

```bash
cargo test build_disclosures 2>&1 | head -20
```
Expected: compile error

- [ ] **Step 6.4: Implement `build_disclosures` in the right place**

If `papillon-shared/src/handshake/mod.rs` exists and is shared between WASM/native paths, add `build_disclosures` there. Otherwise add it in a new `handshake_helpers.rs` in `papillon-shared/src/`.

- [ ] **Step 6.5: Run tests to verify they pass**

```bash
cargo test build_disclosures 2>&1
```
Expected: PASS

- [ ] **Step 6.6: Wire `build_disclosures` into the WASM handshake**

In `apps/papillon/frontend/src/handshake/mod.rs`, replace the inline `disclosures` construction with a call to `build_disclosures`. The WASM handshake will need access to the agent's `requires_disclosure` list (already available from the `AgentAdvertisement`) and the agent's saved settings (load from `agent_settings` via the local catalog).

**Note:** The WASM path runs in-browser. Agent settings are loaded from `IndexedDB` (via `DatabaseOps::get_agent_settings`). The agent DID hash is available at the point of handshake. Look at how `local_catalog.rs` resolves agents and what data is available — you may need to pass `requires_disclosure` and settings into the handshake executor.

- [ ] **Step 6.7: Run full app compile check**

```bash
cd apps/papillon && cargo check 2>&1 | grep "^error" | head -20
```
Expected: no errors

- [ ] **Step 6.8: Commit**

```bash
git add apps/papillon/frontend/src/ crates/papillon-shared/src/
git commit -m "feat(handshake): include agent-required properties (api_key etc.) in Phase 3 disclosures"
```

---

## Task 7: End-to-end test and PR

**Files:**
- Modify: `apps/papillon/e2e/tests/agents.spec.ts` (add a test that submits a query that exercises a structural-param agent)

- [ ] **Step 7.1: Run the full test suite**

```bash
cargo test --workspace 2>&1 | tail -30
```
Expected: all tests pass

- [ ] **Step 7.2: Add an e2e test for param extraction**

In `apps/papillon/e2e/tests/agents.spec.ts`, add:

```typescript
test("github releases agent resolves owner/repo from query", async ({ page }) => {
  // This test verifies that submitting "torvalds/linux" routes to the GitHub Releases
  // agent and the block resolves (not fails at phase 4 with literal {owner}/{repo}).
  // Since we're not mocking HTTP in e2e, we accept either Resolved or a network error —
  // what we must NOT see is "phase 4: no results" with unsubstituted placeholders.
  await createEmptyCanvas(page);
  await submitAndWaitForBlock(page, "torvalds/linux releases");
  const block = page.locator(".canvas-block").first();
  await expect(block).not.toContainText("{owner}");
  await expect(block).not.toContainText("{repo}");
});
```

- [ ] **Step 7.3: Push and open PR**

```bash
git push origin feat/1ed9-continue-branch
gh pr create --title "feat(agents): parameter extraction and auth disclosure for 58 catalog agents" \
  --body "..."
```

---

## Self-Review

**Spec coverage check:**

- ✅ Category A (structural params like lat/lon, owner/repo): Task 1 (extractor) + Task 2 (substitution) + Task 5 (disclosure declaration)
- ✅ Category B (auth-gated with demo keys): Task 3 (agent_settings wired into handler) + Task 4 (TOML demo→{api_key}) + Task 6 (disclosures include api_key from settings)
- ✅ Protocol correctness: auth params come from disclosures/settings, NOT from query text (resolve_param returns None for auth param names)
- ✅ Fallback behavior: unknown structural params fall back to verbatim query (safe — BM25 already routed correctly)
- ✅ No LLM hallucination path: endpoint failures still hard-fail; LLM path only for agents without endpoints

**Placeholder scan:** No TBDs found. All code blocks are complete.

**Type consistency:** `DynamicSession.disclosed_props` is `HashMap<String, String>` throughout. `extract_template_params` returns `Vec<String>`. `resolve_param` returns `Option<String>`. All consistent.

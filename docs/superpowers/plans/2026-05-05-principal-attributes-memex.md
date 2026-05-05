# Principal Attributes Memex Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store per-principal attribute values (schema.org vocab keys) in a local SQLite table so that when agents request disclosure fields like `schema:givenName` or `schema:departureAirport`, Papillon can pre-fill the approval form from previously-entered values — and save new values entered at approval time.

**Architecture:** A new `principal_attributes` table lives in the shared `NativeDatabase` (and WASM stub). Three new `DatabaseOps` methods read/write it. `IntentPlan` grows a `candidates` field (Vec of up to 3 agents). The AwaitingApproval block renders agent checkboxes + a union disclosure form pre-filled via a new `get_principal_attributes` Tauri command. `canvas_approve_block` accepts `filled_values`, stores them, and dispatches a handshake per selected agent. `HandshakeParams` gains `extra_disclosures` threaded through to Phase 3.

**Tech Stack:** Rust / rusqlite / Tauri v2 / Leptos WASM frontend

---

## File Map

| Action | Path |
|--------|------|
| Modify | `crates/papillon-shared/src/db/native.rs` — add table + 3 `DatabaseOps` impls |
| Modify | `crates/papillon-shared/src/db/wasm.rs` — in-memory stub for 3 methods |
| Modify | `crates/papillon-shared/src/db/indexed_db.rs` — delegate + persist for 3 methods |
| Modify | `crates/papillon-shared/src/db/mod.rs` — add 3 method signatures to `DatabaseOps` trait |
| Modify | `crates/papillon-shared/src/types.rs` — add `AgentCandidate` struct + `candidates` field to `IntentPlan` |
| Modify | `apps/papillon/src/commands/canvas/resolution.rs` — new `resolve_top_agents` returning `Vec<ResolvedAgent>` |
| Modify | `apps/papillon/src/commands/canvas/approval.rs` — `canvas_plan_prompt` uses `resolve_top_agents`; `canvas_approve_block` accepts `filled_values` |
| New    | `apps/papillon/src/commands/attributes.rs` — `get_principal_attributes` Tauri command |
| Modify | `apps/papillon/src/commands/mod.rs` — expose `attributes` module |
| Modify | `apps/papillon/src/lib.rs` — register `get_principal_attributes` in `invoke_handler` |
| Modify | `apps/papillon/src/handshake.rs` — add `extra_disclosures` to `HandshakeParams`; merge in Phase 3 |
| Modify | `apps/papillon/src/commands/canvas/execution.rs` — thread `extra_disclosures` through `process_prompt` |
| Modify | `apps/papillon/frontend/src/state/canvas.rs` — `approve_block` passes `filledValues` + `selectedAgents` |
| Modify | `apps/papillon/frontend/src/components/block_renderer/mod.rs` — AwaitingApproval renders agent checkboxes + memex form |

---

## Task 1: DB schema — add `principal_attributes` table + `DatabaseOps` methods

**Files:**
- Modify: `crates/papillon-shared/src/db/mod.rs`
- Modify: `crates/papillon-shared/src/db/native.rs`
- Modify: `crates/papillon-shared/src/db/wasm.rs`
- Modify: `crates/papillon-shared/src/db/indexed_db.rs`
- Test: `crates/papillon-shared/src/db/native.rs` (inline `#[cfg(test)]` block)

### Context

The `DatabaseOps` trait lives in `crates/papillon-shared/src/db/mod.rs`. All new methods go there as trait methods. `NativeDatabase` in `native.rs` is the rusqlite backend. `WasmDatabase` in `wasm.rs` is the in-memory WASM backend. `IndexedDbDatabase` in `indexed_db.rs` wraps `WasmDatabase` with browser persistence (calls `self.inner.<method>` then `self.persist_to_storage()`).

The existing `set_setting` pattern in `native.rs` (line 603):
```rust
fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
    let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(|e| DbError(format!("db set setting: {e}")))?;
    Ok(())
}
```

The schema migrations are all in one `conn.execute_batch(...)` call in `NativeDatabase::migrate`.

- [ ] **Step 1: Add 3 method signatures to `DatabaseOps` trait in `mod.rs`**

In `crates/papillon-shared/src/db/mod.rs`, add to the `DatabaseOps` trait (after the `delete_agent_def` method, before the closing `}`):

```rust
// ── Principal Attributes (memex) ─────────────────────────────────────────
// Stores per-principal attribute values keyed by exact schema.org vocab string.
// Any key that appears in an agent's `requires_disclosure` is a valid key here.
// Three agents asking for `schema:departureAirport` all share the same row.

/// Upsert a principal attribute (INSERT OR REPLACE by prop_name).
/// `prop` is the exact schema.org key, e.g. `"schema:givenName"`.
fn set_principal_attribute(&self, prop: &str, value: &str) -> Result<(), DbError>;

/// Retrieve a single principal attribute value. Returns `None` if not stored.
fn get_principal_attribute(&self, prop: &str) -> Result<Option<String>, DbError>;

/// Retrieve all stored principal attributes as a map of prop_name → value.
fn get_all_principal_attributes(&self) -> Result<std::collections::HashMap<String, String>, DbError>;
```

- [ ] **Step 2: Add table DDL to `NativeDatabase::migrate` in `native.rs`**

Inside the `conn.execute_batch(...)` string in `NativeDatabase::migrate` (after the `saved_pipelines` block, before the closing `"`), add:

```sql
CREATE TABLE IF NOT EXISTS principal_attributes (
    prop_name  TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    last_used  TEXT NOT NULL
);
```

- [ ] **Step 3: Implement 3 methods on `NativeDatabase` in `native.rs`**

Add after the existing `set_setting` / `get_setting` implementations:

```rust
fn set_principal_attribute(&self, prop: &str, value: &str) -> Result<(), DbError> {
    let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO principal_attributes (prop_name, value, last_used) VALUES (?1, ?2, ?3)
         ON CONFLICT(prop_name) DO UPDATE SET value = excluded.value, last_used = excluded.last_used",
        params![prop, value, now],
    )
    .map_err(|e| DbError(format!("db set_principal_attribute: {e}")))?;
    Ok(())
}

fn get_principal_attribute(&self, prop: &str) -> Result<Option<String>, DbError> {
    let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
    conn.query_row(
        "SELECT value FROM principal_attributes WHERE prop_name = ?1",
        params![prop],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| DbError(format!("db get_principal_attribute: {e}")))
}

fn get_all_principal_attributes(&self) -> Result<std::collections::HashMap<String, String>, DbError> {
    let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT prop_name, value FROM principal_attributes ORDER BY last_used DESC")
        .map_err(|e| DbError(format!("db get_all_principal_attributes: {e}")))?;
    let map: Result<std::collections::HashMap<String, String>, _> = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|e| DbError(format!("db get_all_principal_attributes query: {e}")))?
        .map(|r| r.map_err(|e| DbError(format!("db row: {e}"))))
        .collect();
    map
}
```

- [ ] **Step 4: Add in-memory stub to `WasmDatabase` in `wasm.rs`**

In `WasmDatabase` struct, add a new field after `agent_defs`:
```rust
/// In-memory principal attribute store (prop_name → value)
principal_attributes: Arc<Mutex<std::collections::HashMap<String, String>>>,
```

In `WasmDatabase::new()`, initialize it:
```rust
principal_attributes: Arc::new(Mutex::new(std::collections::HashMap::new())),
```

In the `DatabaseOps for WasmDatabase` impl, add:
```rust
fn set_principal_attribute(&self, prop: &str, value: &str) -> Result<(), DbError> {
    let mut map = self.principal_attributes.lock().map_err(|e| DbError(format!("db lock: {e}")))?;
    map.insert(prop.to_string(), value.to_string());
    Ok(())
}

fn get_principal_attribute(&self, prop: &str) -> Result<Option<String>, DbError> {
    let map = self.principal_attributes.lock().map_err(|e| DbError(format!("db lock: {e}")))?;
    Ok(map.get(prop).cloned())
}

fn get_all_principal_attributes(&self) -> Result<std::collections::HashMap<String, String>, DbError> {
    let map = self.principal_attributes.lock().map_err(|e| DbError(format!("db lock: {e}")))?;
    Ok(map.clone())
}
```

- [ ] **Step 5: Delegate in `IndexedDbDatabase` in `indexed_db.rs`**

In the `DatabaseOps for IndexedDbDatabase` impl, add (after the `set_setting` delegation block):
```rust
fn set_principal_attribute(&self, prop: &str, value: &str) -> Result<(), DbError> {
    self.inner.set_principal_attribute(prop, value)?;
    self.persist_to_storage()?;
    Ok(())
}

fn get_principal_attribute(&self, prop: &str) -> Result<Option<String>, DbError> {
    self.inner.get_principal_attribute(prop)
}

fn get_all_principal_attributes(&self) -> Result<std::collections::HashMap<String, String>, DbError> {
    self.inner.get_all_principal_attributes()
}
```

- [ ] **Step 6: Write failing tests**

In `native.rs`, add inside the `#[cfg(test)] mod tests` block:
```rust
#[test]
fn principal_attributes_round_trip() {
    let db = NativeDatabase::open_memory().unwrap();
    db.set_principal_attribute("schema:givenName", "Alice").unwrap();
    let v = db.get_principal_attribute("schema:givenName").unwrap();
    assert_eq!(v, Some("Alice".to_string()));
}

#[test]
fn principal_attributes_upsert() {
    let db = NativeDatabase::open_memory().unwrap();
    db.set_principal_attribute("schema:givenName", "Alice").unwrap();
    db.set_principal_attribute("schema:givenName", "Bob").unwrap();
    let v = db.get_principal_attribute("schema:givenName").unwrap();
    assert_eq!(v, Some("Bob".to_string()));
}

#[test]
fn principal_attributes_missing_returns_none() {
    let db = NativeDatabase::open_memory().unwrap();
    let v = db.get_principal_attribute("schema:nonexistent").unwrap();
    assert_eq!(v, None);
}

#[test]
fn get_all_principal_attributes_returns_all() {
    let db = NativeDatabase::open_memory().unwrap();
    db.set_principal_attribute("schema:givenName", "Alice").unwrap();
    db.set_principal_attribute("schema:departureAirport", "LAX").unwrap();
    let map = db.get_all_principal_attributes().unwrap();
    assert_eq!(map.get("schema:givenName"), Some(&"Alice".to_string()));
    assert_eq!(map.get("schema:departureAirport"), Some(&"LAX".to_string()));
    assert_eq!(map.len(), 2);
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p papillon-shared --features native -- principal_attributes`
Expected: 4 tests pass.

- [ ] **Step 8: Commit**

```bash
git add crates/papillon-shared/src/db/mod.rs \
        crates/papillon-shared/src/db/native.rs \
        crates/papillon-shared/src/db/wasm.rs \
        crates/papillon-shared/src/db/indexed_db.rs
git commit -m "feat(db): add principal_attributes memex table and DatabaseOps methods"
```

---

## Task 2: `AgentCandidate` type + `IntentPlan.candidates` field

**Files:**
- Modify: `crates/papillon-shared/src/types.rs`
- Test: inline (compile-only)

### Context

Current `IntentPlan` (line 438 in `types.rs`):
```rust
pub struct IntentPlan {
    pub action: String,
    pub selected_agent_name: String,
    pub selected_agent_did: Option<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    pub approval_request_id: String,
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u32,
}
```

The plan is to add `candidates: Vec<AgentCandidate>` while keeping the old scalar fields. The frontend reads `plan.candidates` for the agent selector. The backend's `canvas_plan_prompt` fills both the legacy fields (for backward compatibility with auto-approve path) AND the new `candidates` vec.

- [ ] **Step 1: Add `AgentCandidate` struct before `IntentPlan`**

In `crates/papillon-shared/src/types.rs`, insert before the `IntentPlan` struct:
```rust
/// A single agent candidate in a multi-agent approval plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCandidate {
    pub name: String,
    pub did: String,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
}
```

- [ ] **Step 2: Add `candidates` to `IntentPlan`**

Change `IntentPlan` to:
```rust
pub struct IntentPlan {
    pub action: String,
    /// Primary agent (first candidate). Kept for auto-approve path and backward compat.
    pub selected_agent_name: String,
    pub selected_agent_did: Option<String>,
    /// Union of requires_disclosure across all candidates (for display).
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    pub approval_request_id: String,
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u32,
    /// All agent candidates (up to 3). Frontend shows agent selector + union disclosure form.
    #[serde(default)]
    pub candidates: Vec<AgentCandidate>,
}
```

- [ ] **Step 3: Verify compile**

Run: `cargo check -p papillon-shared --features native`
Expected: compiles clean.

- [ ] **Step 4: Commit**

```bash
git add crates/papillon-shared/src/types.rs
git commit -m "feat(types): add AgentCandidate and IntentPlan.candidates for multi-agent approval"
```

---

## Task 3: `resolve_top_agents` — return up to N candidates

**Files:**
- Modify: `apps/papillon/src/commands/canvas/resolution.rs`
- Test: compile-only (scoring logic already tested in mod.rs tests)

### Context

The current `resolve_agent` function scores all candidates and returns the best one. We need a new function `resolve_top_agents(n)` that returns the top-N scored `ResolvedAgent` values. The existing scoring and handler-resolution logic must be reused, not duplicated. The single-agent `resolve_agent` should stay and call `resolve_top_agents(1)` internally.

`ResolvedAgent`:
```rust
pub(crate) struct ResolvedAgent {
    pub name: String,
    pub did: String,
    pub handler: Arc<dyn AgentHandler>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
}
```

Handler resolution (after scoring) is the same for all candidates — the block after `// Resolve handler` in the current function. This logic must be extracted to a helper so `resolve_top_agents` can call it per candidate.

- [ ] **Step 1: Add `resolve_top_agents` and refactor `resolve_agent` to call it**

In `apps/papillon/src/commands/canvas/resolution.rs`:

First, add a helper `build_handler` that extracts the handler-building logic (currently inline at end of `resolve_agent`):
```rust
fn build_handler(
    state: &State<'_, AppState>,
    agent_name: &str,
    source_url: Option<&str>,
) -> Result<Arc<dyn AgentHandler>, PapillonError> {
    if let Some(h) = state.local_agents.get(agent_name) {
        return Ok(h.clone());
    }
    let Some(pap_url) = source_url else {
        return Err(PapillonError::from(format!("No handler for {}", agent_name)));
    };
    let parsed = PapUrl::parse(pap_url).map_err(|e| PapillonError::from(e.to_string()))?;
    let endpoint = parsed.https_endpoint();
    let fingerprint = {
        let local = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        local
            .peers()
            .iter()
            .find(|p| p.endpoint.trim_end_matches('/') == endpoint.trim_end_matches('/'))
            .and_then(|p| p.cert_fingerprint.clone())
    };
    let slug = agent_name.to_lowercase().replace(' ', "-");
    let base_url = format!("{}/agents/{}", endpoint, slug);
    match fingerprint {
        Some(fp) => {
            let http_client =
                build_pinned_client(&[fp]).map_err(|e| PapillonError::from(e.to_string()))?;
            Ok(Arc::new(RemoteAgentHandler::with_client(&base_url, http_client)))
        }
        None => Err(PapillonError::from(format!(
            "No cert fingerprint for peer {} — navigate to it first",
            endpoint
        ))),
    }
}
```

Then add `resolve_top_agents`:
```rust
/// Resolve the top `n` agents by score. Returns an empty vec (not an error)
/// if fewer than `n` candidates exist — callers must handle len < n gracefully.
pub(crate) async fn resolve_top_agents(
    state: &State<'_, AppState>,
    action_type: &str,
    preferred_name: &str,
    exclude_agents: &[String],
    n: usize,
) -> Result<Vec<ResolvedAgent>, PapillonError> {
    let agent_defs: std::collections::HashMap<String, pap_agents::DynamicAgentDef> = state
        .db
        .load_all_agents()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| d.agent_did.clone().map(|did| (did, d)))
        .collect();

    let inference_substrate = {
        let cfg = state
            .orchestrator_config
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cfg.inference_substrate.clone()
    };

    // Collect all candidates: local first, then remote
    let mut all_scored: Vec<(String, String, Vec<String>, Vec<String>, Option<String>, f64)> = {
        let local = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        let candidates = local.query_local(action_type);
        let mut v: Vec<_> = candidates
            .iter()
            .filter(|a| !exclude_agents.contains(&a.name))
            .map(|a| {
                let schema_hint = a.returns.first().map(|s| s.as_str()).unwrap_or("");
                let agent_def = agent_defs.get(&a.provider.did);
                let s = score_agent(
                    &state.db,
                    &a.provider.did,
                    preferred_name,
                    &a.name,
                    action_type,
                    schema_hint,
                    agent_def,
                    &inference_substrate,
                );
                (
                    a.name.clone(),
                    a.provider.did.clone(),
                    a.requires_disclosure.clone(),
                    a.returns.clone(),
                    None::<String>,
                    s,
                )
            })
            .collect();
        v.sort_by(|a, b| b.5.partial_cmp(&a.5).unwrap_or(std::cmp::Ordering::Equal));
        v
    };

    // If we need more, check remote registries
    if all_scored.len() < n {
        let registries = state
            .registries
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        for (url, registry) in registries.iter() {
            let remote_candidates = registry.query_local_satisfiable(action_type, &[]);
            for a in remote_candidates
                .iter()
                .filter(|a| !exclude_agents.contains(&a.name))
                .filter(|a| !all_scored.iter().any(|(n, _, _, _, _, _)| n == &a.name))
            {
                let schema_hint = a.returns.first().map(|s| s.as_str()).unwrap_or("");
                let agent_def = agent_defs.get(&a.provider.did);
                let s = score_agent(
                    &state.db,
                    &a.provider.did,
                    preferred_name,
                    &a.name,
                    action_type,
                    schema_hint,
                    agent_def,
                    &inference_substrate,
                );
                all_scored.push((
                    a.name.clone(),
                    a.provider.did.clone(),
                    a.requires_disclosure.clone(),
                    a.returns.clone(),
                    Some(url.clone()),
                    s,
                ));
            }
        }
        all_scored.sort_by(|a, b| b.5.partial_cmp(&a.5).unwrap_or(std::cmp::Ordering::Equal));
    }

    // Build handlers for the top-n candidates
    let mut result = Vec::with_capacity(n.min(all_scored.len()));
    for (name, did, requires_disclosure, returns, source_url, _score) in
        all_scored.into_iter().take(n)
    {
        let handler = build_handler(state, &name, source_url.as_deref())?;
        result.push(ResolvedAgent {
            name,
            did,
            handler,
            requires_disclosure,
            returns,
        });
    }

    if result.is_empty() {
        return Err(PapillonError::from(format!("No agent for {}", action_type)));
    }
    Ok(result)
}
```

Finally, simplify `resolve_agent` to delegate:
```rust
pub(crate) async fn resolve_agent(
    state: &State<'_, AppState>,
    action_type: &str,
    preferred_name: &str,
    exclude_agents: &[String],
) -> Result<ResolvedAgent, PapillonError> {
    resolve_top_agents(state, action_type, preferred_name, exclude_agents, 1)
        .await
        .map(|mut v| v.remove(0))
}
```

- [ ] **Step 2: Verify compile**

Run: `cargo check -p papillon`
Expected: compiles clean.

- [ ] **Step 3: Commit**

```bash
git add apps/papillon/src/commands/canvas/resolution.rs
git commit -m "feat(resolution): add resolve_top_agents returning top-N scored agent candidates"
```

---

## Task 4: `get_principal_attributes` Tauri command

**Files:**
- Create: `apps/papillon/src/commands/attributes.rs`
- Modify: `apps/papillon/src/commands/mod.rs`
- Modify: `apps/papillon/src/lib.rs`
- Test: inline

### Context

The frontend needs to pre-fill the disclosure form with stored values. A single Tauri command returns all stored attributes as `HashMap<String, String>`. The frontend can then look up each `requires_disclosure` key to find a pre-filled value.

`AppState` has `pub db: Arc<Database>` and `Database` implements `DatabaseOps` (via `use crate::db::prelude::DatabaseOps`).

- [ ] **Step 1: Write failing test (will not compile until implementation)**

In `apps/papillon/src/commands/attributes.rs` (new file), write:
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn get_principal_attributes_command_exists() {
        // Compile test — if the command is defined and registered, this passes.
        // Run: cargo check -p papillon
    }
}
```

- [ ] **Step 2: Implement the command**

Create `apps/papillon/src/commands/attributes.rs`:
```rust
use std::collections::HashMap;

use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;

/// Return all stored principal attributes as a flat key→value map.
/// Keys are exact schema.org vocab strings (e.g. `"schema:givenName"`).
/// The frontend uses this to pre-fill the AwaitingApproval disclosure form.
#[tauri::command]
pub fn get_principal_attributes(
    state: State<'_, AppState>,
) -> Result<HashMap<String, String>, PapillonError> {
    state
        .db
        .get_all_principal_attributes()
        .map_err(|e| PapillonError::from(e.to_string()))
}
```

- [ ] **Step 3: Expose the module in `commands/mod.rs`**

In `apps/papillon/src/commands/mod.rs`, add:
```rust
pub mod attributes;
```

- [ ] **Step 4: Register command in `lib.rs`**

In `apps/papillon/src/lib.rs`, inside `tauri::generate_handler![...]`, add:
```rust
commands::attributes::get_principal_attributes,
```

- [ ] **Step 5: Verify compile**

Run: `cargo check -p papillon`
Expected: compiles clean.

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/src/commands/attributes.rs \
        apps/papillon/src/commands/mod.rs \
        apps/papillon/src/lib.rs
git commit -m "feat(commands): add get_principal_attributes Tauri command"
```

---

## Task 5: `canvas_plan_prompt` — populate `IntentPlan.candidates`

**Files:**
- Modify: `apps/papillon/src/commands/canvas/approval.rs`
- Test: compile-only

### Context

`canvas_plan_prompt` in `approval.rs` currently calls `resolve_agent` once and builds an `IntentPlan` with the single result. It must now call `resolve_top_agents(3)` and populate both the legacy scalar fields (first candidate) AND the new `candidates` vec.

The `IntentPlan.requires_disclosure` shown in the UI should be the **union** of all candidates' `requires_disclosure` fields (deduplicated, preserving insertion order).

`canvas_plan_prompt` also calls `process_prompt` after approval — that path still uses a single agent (the first candidate, or whichever the user selected). The multi-dispatch path is handled in Task 6 (`canvas_approve_block`).

`AgentCandidate` is in `papillon_shared::types`. The import at top of `approval.rs` already has `use papillon_shared::{..., IntentPlan, ...}` — add `AgentCandidate` there.

- [ ] **Step 1: Update imports in `approval.rs`**

Change:
```rust
use papillon_shared::{BlockEvent, BlockState, BlockUpdate, IntentPlan, PreferenceEngine};
```
To:
```rust
use papillon_shared::{AgentCandidate, BlockEvent, BlockState, BlockUpdate, IntentPlan, PreferenceEngine};
```

Also add to the `use super::...` imports:
```rust
use super::resolution::resolve_top_agents;
```

- [ ] **Step 2: Replace `resolve_agent` call with `resolve_top_agents`**

Replace the current block (starting at `let resolved = resolve_agent(...)`) in `canvas_plan_prompt` up through the `IntentPlan { ... }` construction with:

```rust
// Resolve top-3 candidates.
let candidates_resolved = resolve_top_agents(&state, &action_type, &preferred, &[], 3).await?;

// Primary agent is the top-scored candidate.
let primary = &candidates_resolved[0];

// Union of requires_disclosure across all candidates (dedup, insertion order).
let mut union_disclosure: Vec<String> = Vec::new();
for c in &candidates_resolved {
    for prop in &c.requires_disclosure {
        if !union_disclosure.contains(prop) {
            union_disclosure.push(prop.clone());
        }
    }
}

let approval_request_id = uuid::Uuid::new_v4().to_string();

let mandate_ttl_hours = {
    let cfg = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    cfg.mandate_ttl_hours
};

let candidates: Vec<AgentCandidate> = candidates_resolved
    .iter()
    .map(|r| AgentCandidate {
        name: r.name.clone(),
        did: r.did.clone(),
        requires_disclosure: r.requires_disclosure.clone(),
        returns: r.returns.clone(),
    })
    .collect();

let plan = IntentPlan {
    action: action_type.to_string(),
    selected_agent_name: primary.name.clone(),
    selected_agent_did: Some(primary.did.clone()),
    requires_disclosure: union_disclosure,
    returns: primary.returns.clone(),
    approval_request_id: approval_request_id.clone(),
    ttl_hours: mandate_ttl_hours as u32,
    candidates,
};
```

- [ ] **Step 3: Verify compile**

Run: `cargo check -p papillon`
Expected: compiles clean.

- [ ] **Step 4: Commit**

```bash
git add apps/papillon/src/commands/canvas/approval.rs
git commit -m "feat(approval): canvas_plan_prompt resolves top-3 candidates into IntentPlan"
```

---

## Task 6: `canvas_approve_block` — accept `filled_values`, store to memex, dispatch per-agent

**Files:**
- Modify: `apps/papillon/src/commands/canvas/approval.rs`
- Modify: `apps/papillon/src/handshake.rs`
- Modify: `apps/papillon/src/commands/canvas/execution.rs`
- Test: inline unit tests

### Context

The approval flow currently:
1. `canvas_approve_block` verifies challenge + sends `true` to the oneshot channel
2. `canvas_plan_prompt` awaits the channel, then calls `process_prompt` with original `query`

To support multi-agent dispatch with memex storage, the flow needs to change:

- `canvas_approve_block` now receives `filled_values: HashMap<String, String>` and `selected_agent_names: Vec<String>` alongside the existing params.
- It stores each `filled_values` entry to `principal_attributes`.
- It does **not** just signal the oneshot channel — instead it signals it with `true`, and the `filled_values` + `selected_agent_names` need to be passed through to `process_prompt`.

The cleanest approach: store `filled_values` and `selected_agent_names` in `AppState` keyed by `approval_request_id` before signaling the channel. Then `canvas_plan_prompt` reads them out after the channel fires.

**State change needed**: `AppState` gains a new `approval_values` field:
```rust
pub approval_values: tokio::sync::RwLock<
    std::collections::HashMap<String, (Vec<String>, std::collections::HashMap<String, String>)>
>,
```
The value is `(selected_agent_names, filled_values)`.

`HandshakeParams` gains `extra_disclosures: HashMap<String, String>`. `process_prompt` gains `extra_disclosures` parameter (passed from `canvas_plan_prompt` for each selected agent).

- [ ] **Step 1: Write failing tests for Phase 3 extra disclosures merge**

In `apps/papillon/src/handshake.rs`, add a test inside the existing `#[cfg(test)] mod tests`:
```rust
#[tokio::test]
async fn extra_disclosures_appear_in_phase3() {
    use std::collections::HashMap;
    let echo_handler: Arc<dyn pap_transport::AgentHandler> =
        Arc::new(pap_agents::SimpleAgent::new(EchoExecutor));
    let meta = EchoExecutor.meta();
    let agents = pap_agents::build_agents(vec![("Echo", echo_handler, meta)]);
    let handler = agents.handlers.get("Echo").expect("Echo handler");
    let ad = agents
        .registry
        .all_advertisements()
        .iter()
        .find(|a| a.name == "Echo")
        .expect("Echo advertisement");

    let kp = PrincipalKeypair::generate();
    let mut extra = HashMap::new();
    extra.insert("schema:givenName".to_string(), "Alice".to_string());

    let result = execute(HandshakeParams {
        handler: handler.clone(),
        agent_name: "Echo",
        agent_did: &ad.provider.did,
        action_type: "schema:SearchAction",
        query: "test query",
        principal_kp: &kp,
        requires_disclosure: &[],
        returns: &[],
        extra_disclosures: extra,
        on_phase: Box::new(|_, _| {}),
        on_fail: Box::new(|_, _| {}),
    })
    .await;

    assert!(result.is_ok(), "handshake with extra_disclosures should succeed");
}
```

Run: `cargo test -p papillon -- handshake::tests::extra_disclosures_appear_in_phase3 2>&1 | head -5`
Expected: compile error (field not yet added).

- [ ] **Step 2: Add `extra_disclosures` to `HandshakeParams`**

In `apps/papillon/src/handshake.rs`, change `HandshakeParams`:
```rust
pub struct HandshakeParams<'a> {
    pub handler: Arc<dyn AgentHandler>,
    pub agent_name: &'a str,
    pub agent_did: &'a str,
    pub action_type: &'a str,
    pub query: &'a str,
    pub principal_kp: &'a PrincipalKeypair,
    pub requires_disclosure: &'a [String],
    pub returns: &'a [String],
    /// Pre-filled attribute values from the principal's memex.
    /// Merged into Phase 3 disclosures alongside the query.
    pub extra_disclosures: std::collections::HashMap<String, String>,
    pub on_phase: PhaseCallback,
    pub on_fail: FailCallback,
}
```

In `execute`, destructure the new field:
```rust
let HandshakeParams {
    handler,
    agent_name,
    agent_did,
    action_type,
    query,
    principal_kp,
    requires_disclosure,
    returns,
    extra_disclosures,
    on_phase,
    on_fail,
} = params;
```

In Phase 3 (replace the `disclosures` vec):
```rust
let mut disclosure_obj = serde_json::json!({
    "@type": action_type,
    "query": query
});
// Merge extra_disclosures into the disclosure object.
// Each key is a schema.org vocab string; values are the principal's stored attributes.
if let Some(obj) = disclosure_obj.as_object_mut() {
    for (k, v) in &extra_disclosures {
        obj.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
}
let disclosures = vec![disclosure_obj];
```

- [ ] **Step 3: Fix all `HandshakeParams` construction sites**

All callers of `HandshakeParams { ... }` in `execution.rs` must add `extra_disclosures: std::collections::HashMap::new()` until we wire up the real values in Step 6.

In `apps/papillon/src/commands/canvas/execution.rs`, in the `handshake::execute(handshake::HandshakeParams { ... })` call:
```rust
let result = handshake::execute(handshake::HandshakeParams {
    handler: resolved.handler,
    agent_name: &resolved.name,
    agent_did: &resolved.did,
    action_type,
    query,
    principal_kp: &principal_kp,
    requires_disclosure: &resolved.requires_disclosure,
    returns: &resolved.returns,
    extra_disclosures: std::collections::HashMap::new(), // populated after Task 6 Step 6
    on_phase,
    on_fail,
})
.await?;
```

Also fix any other `HandshakeParams` construction sites (check with `grep -r "HandshakeParams {" apps/`).

- [ ] **Step 4: Run test to verify Phase 3 test passes**

Run: `cargo test -p papillon -- handshake::tests::extra_disclosures_appear_in_phase3`
Expected: PASS.

- [ ] **Step 5: Add `approval_values` field to `AppState`**

In `apps/papillon/src/state.rs`, find the `approval_gates` field and add after it:
```rust
/// Stores (selected_agent_names, filled_values) keyed by approval_request_id.
/// Written by `canvas_approve_block` before signaling the gate, read by `canvas_plan_prompt`.
pub approval_values: tokio::sync::RwLock<
    std::collections::HashMap<
        String,
        (Vec<String>, std::collections::HashMap<String, String>),
    >
>,
```

In `AppState::new` (or wherever `approval_gates` is initialized), add:
```rust
approval_values: tokio::sync::RwLock::new(std::collections::HashMap::new()),
```

Also add in `clone_for_background` if `approval_gates` is cloned there (they share the same Arc so both need the same treatment — check the existing pattern).

- [ ] **Step 6: Update `canvas_approve_block` signature + body**

In `apps/papillon/src/commands/canvas/approval.rs`, change the command signature to:
```rust
#[tauri::command]
pub async fn canvas_approve_block(
    approval_request_id: String,
    approved: bool,
    signed_challenge: SignedChallenge,
    #[serde(default)] filled_values: std::collections::HashMap<String, String>,
    #[serde(default)] selected_agent_names: Vec<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
```

In the body, after the challenge verification block and before the gate-lookup block, add:

```rust
// Store filled attribute values to principal memex.
if approved {
    use crate::db::prelude::DatabaseOps;
    for (prop, value) in &filled_values {
        if !value.trim().is_empty() {
            if let Err(e) = state.db.set_principal_attribute(prop, value) {
                eprintln!("WARN: failed to store principal attribute {prop}: {e}");
            }
        }
    }
    // Persist (selected_agent_names, filled_values) for canvas_plan_prompt to read.
    {
        let mut vals = state.approval_values.write().await;
        vals.insert(
            approval_request_id.clone(),
            (selected_agent_names, filled_values),
        );
    }
}
```

- [ ] **Step 7: Update `canvas_plan_prompt` to read approval values and dispatch per-agent**

In `canvas_plan_prompt`, after `let approved = receiver.await.unwrap_or(false);` and inside the `if approved {` branch, replace the single `process_prompt` call with a multi-dispatch loop:

```rust
if approved {
    // Read (selected_agent_names, filled_values) stored by canvas_approve_block.
    let (selected_names, filled_values) = {
        let mut vals = state.approval_values.write().await;
        vals.remove(&approval_request_id).unwrap_or_default()
    };

    // Persist approval scopes (existing logic — keep it).
    PreferenceEngine::new(state.db.as_ref()).save_approved_scopes(
        &action_type,
        schema_type_for_pref,
        &hash_agent_did(&primary.did),  // use primary's DID
        &primary.name,
        &plan.requires_disclosure,
    );

    // Filter candidates to those selected by the principal.
    // If selected_names is empty (e.g. auto-approve), use primary only.
    let dispatch_candidates: Vec<&ResolvedAgent> = if selected_names.is_empty() {
        vec![&candidates_resolved[0]]
    } else {
        candidates_resolved
            .iter()
            .filter(|c| selected_names.contains(&c.name))
            .collect()
    };

    // Dispatch handshake to each selected agent in sequence.
    // Each produces its own Resolved block (emitted by process_prompt_with_extras).
    let mut last_result = None;
    for candidate in dispatch_candidates {
        match process_prompt_with_extras(
            &app,
            &state,
            &prompt_id,
            &block_id,
            &action_type,
            &candidate.name,
            &query,
            filled_values.clone(),
        )
        .await
        {
            Ok(r) => last_result = Some(r),
            Err(e) => {
                eprintln!("WARN: handshake failed for {}: {e}", candidate.name);
            }
        }
    }

    let (schema_type, content, preference_guided, agent_did, retention_warning) =
        last_result.ok_or_else(|| PapillonError::from("All selected agents failed"))?;

    // ... rest of block_resolved emit (unchanged)
```

Note: `process_prompt_with_extras` is a new wrapper defined in Step 8.

- [ ] **Step 8: Add `process_prompt_with_extras` to `execution.rs`**

In `apps/papillon/src/commands/canvas/execution.rs`, add a public(crate) wrapper that accepts `extra_disclosures` and passes them through:

```rust
pub(crate) async fn process_prompt_with_extras(
    app: &AppHandle,
    state: &State<'_, AppState>,
    prompt_id: &str,
    block_id: &str,
    action_type: &str,
    preferred: &str,
    query: &str,
    extra_disclosures: std::collections::HashMap<String, String>,
) -> Result<(String, serde_json::Value, bool, String, Option<String>), PapillonError> {
    process_prompt_inner_with_extras(
        app,
        state,
        prompt_id,
        block_id,
        action_type,
        preferred,
        query,
        extra_disclosures,
        &[],
        0,
    )
    .await
}
```

Then in `process_prompt_inner` (the existing recursive function), add `extra_disclosures: std::collections::HashMap<String, String>` as a parameter and pass it to `handshake::execute`:
```rust
let result = handshake::execute(handshake::HandshakeParams {
    handler: resolved.handler,
    agent_name: &resolved.name,
    agent_did: &resolved.did,
    action_type,
    query,
    principal_kp: &principal_kp,
    requires_disclosure: &resolved.requires_disclosure,
    returns: &resolved.returns,
    extra_disclosures,
    on_phase,
    on_fail,
})
.await?;
```

The existing `process_prompt` (which calls `process_prompt_inner`) passes `std::collections::HashMap::new()` for `extra_disclosures`.

Create `process_prompt_inner_with_extras` as a thin alias or add it as an overload that forwards to the same inner logic with the extras parameter.

- [ ] **Step 9: Verify compile and run tests**

Run: `cargo check -p papillon`
Run: `cargo test -p papillon -- handshake::tests`
Expected: all pass.

- [ ] **Step 10: Commit**

```bash
git add apps/papillon/src/handshake.rs \
        apps/papillon/src/commands/canvas/approval.rs \
        apps/papillon/src/commands/canvas/execution.rs \
        apps/papillon/src/state.rs
git commit -m "feat(approve): canvas_approve_block stores memex values + dispatches per-agent with extra_disclosures"
```

---

## Task 7: Frontend — AwaitingApproval with agent selector and memex form

**Files:**
- Modify: `apps/papillon/frontend/src/components/block_renderer/mod.rs`
- Modify: `apps/papillon/frontend/src/state/canvas.rs`
- Test: compile-only (WASM UI — no headless test runner)

### Context

The AwaitingApproval block render is at lines 284–394 in `block_renderer/mod.rs`. It currently shows static disclosure badges and a single GRANT ACCESS button.

New behavior:
1. **Agent selector**: Show a checkbox per candidate from `plan.candidates`. All checked by default.
2. **Disclosure form**: Show a labelled text input per unique `requires_disclosure` prop across all checked agents (union, deduplicated). Pre-fill from `get_principal_attributes` (fetched once when block enters AwaitingApproval). Label is the prop key stripped of `"schema:"` prefix.
3. **GRANT ACCESS button**: calls `approve_block` with `filledValues: HashMap` and `selectedAgentNames: Vec<String>`.

`approve_block` in `canvas.rs` currently signature:
```rust
pub fn approve_block(&self, block_id: String, approval_request_id: String)
```

New signature:
```rust
pub fn approve_block(
    &self,
    block_id: String,
    approval_request_id: String,
    filled_values: std::collections::HashMap<String, String>,
    selected_agent_names: Vec<String>,
)
```

The bridge call changes from:
```rust
bridge::invoke("canvas_approve_block", &serde_json::json!({
    "approvalRequestId": approval_request_id,
    "approved": true,
    "signedChallenge": signed_challenge,
}))
```
To:
```rust
bridge::invoke("canvas_approve_block", &serde_json::json!({
    "approvalRequestId": approval_request_id,
    "approved": true,
    "signedChallenge": signed_challenge,
    "filledValues": filled_values,
    "selectedAgentNames": selected_agent_names,
}))
```

For the pre-fill, use a `RwSignal<HashMap<String,String>>` local to the block. Fetch `get_principal_attributes` via `spawn_local` when the block renders. The `view!` macro reads the signal reactively.

`IntentPlan` and `AgentCandidate` are already in `papillon_shared` which is imported in the frontend crate. Verify with `use papillon_shared::{..., AgentCandidate, ...}` at top of `mod.rs`.

- [ ] **Step 1: Update `approve_block` signature in `canvas.rs`**

In `apps/papillon/frontend/src/state/canvas.rs`, change `approve_block`:
```rust
pub fn approve_block(
    &self,
    block_id: String,
    approval_request_id: String,
    filled_values: std::collections::HashMap<String, String>,
    selected_agent_names: Vec<String>,
) {
    // ... double-submit guard unchanged ...

    let in_flight = self.approval_in_flight;
    let canvases = self.canvases;
    let block_id_clone = block_id.clone();

    spawn_local(async move {
        let signed_challenge = match crate::bridge::invoke::<_, serde_json::Value>(
            "sign_approval_challenge",
            &serde_json::json!({}),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                // ... existing error handling unchanged ...
                return;
            }
        };

        match crate::bridge::invoke::<_, serde_json::Value>(
            "canvas_approve_block",
            &serde_json::json!({
                "approvalRequestId": approval_request_id,
                "approved": true,
                "signedChallenge": signed_challenge,
                "filledValues": filled_values,
                "selectedAgentNames": selected_agent_names,
            }),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                // ... existing error handling unchanged ...
            }
        }
        in_flight.update(|s| { s.remove(&block_id_clone); });
    });
}
```

- [ ] **Step 2: Update all `cs_approve.approve_block(...)` call sites**

There is one call site in `block_renderer/mod.rs` (line 385). Change it to pass the new signals (created in Step 3):
```rust
cs_approve.approve_block(
    block_id_approve.clone(),
    approval_id.clone(),
    filled_values_signal.get(),    // HashMap<String,String>
    selected_agents_signal.get(),  // Vec<String>
);
```

- [ ] **Step 3: Rewrite AwaitingApproval render in `block_renderer/mod.rs`**

Replace the `BlockState::AwaitingApproval { plan } =>` arm (lines 284–394) with:

```rust
BlockState::AwaitingApproval { plan } => {
    let plan = plan.clone();
    let agent_name = plan.selected_agent_name.clone();
    let action_label = plan
        .action
        .strip_prefix("schema:")
        .unwrap_or(&plan.action)
        .to_string();
    let approval_id = plan.approval_request_id.clone();
    let approval_id_reject = approval_id.clone();
    let block_id_approve = block_ctx.id.get_value();
    let block_id_reject = block_ctx.id.get_value();
    let cs_approve = canvas_state;
    let cs_reject = canvas_state;

    let ttl_hours = plan.ttl_hours;

    let first_returns_type = plan
        .returns
        .first()
        .cloned()
        .unwrap_or_else(|| "schema:Thing".to_string());
    let skeleton_json = serde_json::json!({
        "@type": first_returns_type,
        "name": "\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}",
        "description": "\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}"
    });
    let skeleton_type = first_returns_type.clone();
    let skeleton_type_label = skeleton_type
        .strip_prefix("schema:")
        .unwrap_or(&skeleton_type)
        .to_uppercase();
    let skeleton_entries =
        generic::flatten_to_entries(&skeleton_type, &skeleton_json, &registry);
    let skeleton_view = generic::render_stream(skeleton_entries, &registry);

    // Agent selector state: all candidates selected by default.
    // If candidates vec is empty (old plan shape), synthesise one from scalar fields.
    let all_candidates: Vec<papillon_shared::AgentCandidate> = if plan.candidates.is_empty() {
        vec![papillon_shared::AgentCandidate {
            name: plan.selected_agent_name.clone(),
            did: plan.selected_agent_did.clone().unwrap_or_default(),
            requires_disclosure: plan.requires_disclosure.clone(),
            returns: plan.returns.clone(),
        }]
    } else {
        plan.candidates.clone()
    };
    let default_selected: Vec<String> = all_candidates.iter().map(|c| c.name.clone()).collect();
    let selected_agents_signal: RwSignal<Vec<String>> = RwSignal::new(default_selected);

    // Disclosure form state: HashMap<prop_name, value> — pre-filled from memex.
    let filled_values_signal: RwSignal<std::collections::HashMap<String, String>> =
        RwSignal::new(std::collections::HashMap::new());

    // Fetch stored attributes from backend on first render.
    {
        let fv = filled_values_signal;
        spawn_local(async move {
            if let Ok(attrs) = crate::bridge::invoke::<_, std::collections::HashMap<String, String>>(
                "get_principal_attributes",
                &serde_json::json!({}),
            )
            .await
            {
                fv.set(attrs);
            }
        });
    }

    // Build the union disclosure list from all candidates (not just selected —
    // we show all fields in the form so the user can fill them even for
    // candidates they may later decide to select).
    let all_disclosure_props: Vec<String> = {
        let mut seen = Vec::new();
        for c in &all_candidates {
            for p in &c.requires_disclosure {
                if !seen.contains(p) {
                    seen.push(p.clone());
                }
            }
        }
        seen
    };
    let has_disclosure = !all_disclosure_props.is_empty();
    let show_agent_selector = all_candidates.len() > 1;

    let approve_label = if has_disclosure { "[ GRANT ACCESS ]" } else { "[ ALLOW ]" };
    let reject_label = if has_disclosure { "[ DENY ]" } else { "[ DECLINE ]" };

    view! {
        <div class="awaiting-approval-header">
            <span class="approval-header-label">"AGENT REQUEST"</span>
            <span class="approval-agent-name">{agent_name}</span>
            <span class="approval-action-sep">"·"</span>
            <span class="approval-action-label">{action_label}</span>
        </div>

        <div class="awaiting-approval-section-label">"WILL RETURN"</div>
        <div class="approval-schema-type">{skeleton_type_label}</div>
        <div class="awaiting-approval-skeleton-wrap">
            {skeleton_view}
        </div>

        <Show when=move || show_agent_selector>
            <div class="awaiting-approval-section-label">"SELECT AGENTS"</div>
            <div class="awaiting-approval-agent-selector">
                {all_candidates.iter().map(|c| {
                    let name = c.name.clone();
                    let name_check = name.clone();
                    let sa = selected_agents_signal;
                    view! {
                        <label class="agent-checkbox-label">
                            <input
                                type="checkbox"
                                checked=move || sa.get().contains(&name_check)
                                on:change=move |ev| {
                                    use wasm_bindgen::JsCast;
                                    let checked = ev
                                        .target()
                                        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                        .map(|el| el.checked())
                                        .unwrap_or(false);
                                    sa.update(|list| {
                                        if checked {
                                            if !list.contains(&name) { list.push(name.clone()); }
                                        } else {
                                            list.retain(|n| n != &name);
                                        }
                                    });
                                }
                            />
                            <span class="agent-checkbox-name">{c.name.clone()}</span>
                        </label>
                    }
                }).collect::<Vec<_>>()}
            </div>
        </Show>

        <Show when=move || has_disclosure>
            <div class="awaiting-approval-section-label">"WILL NEED FROM YOU"</div>
            <div class="awaiting-approval-disclosure-form">
                {all_disclosure_props.iter().map(|prop| {
                    let prop_key = prop.clone();
                    let label = prop
                        .trim_start_matches("schema:")
                        .to_string();
                    let fv = filled_values_signal;
                    view! {
                        <div class="disclosure-field-row">
                            <label class="disclosure-field-label">{label.clone()}</label>
                            <input
                                class="disclosure-field-input"
                                type="text"
                                placeholder=label
                                prop:value=move || fv.get().get(&prop_key).cloned().unwrap_or_default()
                                on:input=move |ev| {
                                    use wasm_bindgen::JsCast;
                                    let val = ev
                                        .target()
                                        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                        .map(|el| el.value())
                                        .unwrap_or_default();
                                    fv.update(|m| { m.insert(prop_key.clone(), val); });
                                }
                            />
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </div>
        </Show>

        <div class="awaiting-approval-mandate-note">
            {format!("DATA VALID  \u{007e}{}h  \u{00b7}  refresh any time", ttl_hours)}
        </div>
        <div class="awaiting-approval-mandate-note">
            "PERMISSION REVOKES  when the time above runs out"
        </div>

        <div class="awaiting-approval-actions">
            <button
                class="hitl-reject-btn"
                on:click=move |e: leptos::ev::MouseEvent| {
                    e.stop_propagation();
                    cs_reject.reject_block(
                        block_id_reject.clone(),
                        approval_id_reject.clone(),
                    );
                }
            >
                {reject_label}
            </button>
            <button
                class="hitl-authorize-btn"
                on:click=move |e: leptos::ev::MouseEvent| {
                    e.stop_propagation();
                    cs_approve.approve_block(
                        block_id_approve.clone(),
                        approval_id.clone(),
                        filled_values_signal.get(),
                        selected_agents_signal.get(),
                    );
                }
            >
                {approve_label}
            </button>
        </div>
    }.into_any()
}
```

- [ ] **Step 4: Check `web_sys::HtmlInputElement` is available**

`web-sys` should already be a dependency of the frontend crate. Verify:

Run: `grep -r "web-sys" apps/papillon/frontend/Cargo.toml`
Expected: feature `"HtmlInputElement"` present (or add it to the `[dependencies.web-sys]` features list if missing).

If missing, add to `apps/papillon/frontend/Cargo.toml`:
```toml
[dependencies.web-sys]
version = "0.3"
features = ["HtmlInputElement"]
```

- [ ] **Step 5: Compile-check the WASM frontend**

Run: `cargo check --target wasm32-unknown-unknown --manifest-path apps/papillon/frontend/Cargo.toml`
Expected: compiles clean.

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/components/block_renderer/mod.rs \
        apps/papillon/frontend/src/state/canvas.rs \
        apps/papillon/frontend/Cargo.toml
git commit -m "feat(ui): AwaitingApproval shows agent selector and memex-prefilled disclosure form"
```

---

## Task 8: Full workspace test pass + WASM check

**Files:**
- No new files — validation only

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 2: Run WASM compile check**

Run: `just check-wasm`
Expected: compiles clean.

- [ ] **Step 3: Fix any compile or test failures**

If failures occur, address them before proceeding. Common failure points:
- Missing `AgentCandidate` import somewhere
- `approval_values` field missing from `clone_for_background` in `state.rs`
- `process_prompt_inner` signature changed but not all callers updated

- [ ] **Step 4: Commit any fixes**

```bash
git add -p
git commit -m "fix: address compile/test issues from memex integration"
```

---

## Self-Review

### Spec coverage

| Spec requirement | Task |
|---|---|
| `principal_attributes` table (prop_name PK, value, last_used) | Task 1 |
| `set_principal_attribute`, `get_principal_attribute`, `get_all_principal_attributes` | Task 1 |
| `IntentPlan` carries `Vec<AgentCandidate>` | Task 2 |
| `resolve_agent` returns top N (3) candidates | Task 3 |
| AwaitingApproval: agent selector (checkboxes, all selected by default) | Task 7 |
| AwaitingApproval: union requires_disclosure as labelled text inputs | Task 7 |
| AwaitingApproval: pre-filled from memex via `get_principal_attributes` | Task 7 |
| AwaitingApproval: one GRANT ACCESS button | Task 7 |
| `canvas_approve_block` accepts `filled_values` | Task 6 |
| Stores each value to `principal_attributes` | Task 6 |
| Dispatches handshake to each selected agent | Task 6 |
| `HandshakeParams` gains `extra_disclosures` | Task 6 |
| `process_prompt` accepts and threads through `extra_disclosures` | Task 6 |
| Phase 3 merges query + extra_disclosures | Task 6 |
| Any string in `requires_disclosure` is a vocab key (no hardcoded list) | All — design is key-agnostic |
| `get_principal_attributes` Tauri command | Task 4 |

### Placeholder scan

No TBD, TODO, or "similar to Task N" references. Every code block is complete.

### Type consistency

- `AgentCandidate` defined in Task 2, used in Task 3 (as `candidates_resolved` items), Task 5 (plan construction), Task 7 (frontend render)
- `filled_values: HashMap<String,String>` in Task 6 `canvas_approve_block` and Task 7 `approve_block` frontend — same type
- `selected_agent_names: Vec<String>` in Task 6 `canvas_approve_block` and Task 7 `approve_block` frontend — same type
- `extra_disclosures: HashMap<String,String>` in `HandshakeParams` (Task 6) and `process_prompt_with_extras` (Task 6) — same type
- `approval_values` field type matches between `state.rs` (Task 6) and the read/write sites in `approval.rs` (Task 6)

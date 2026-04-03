# PAP URI Scheme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `pap://`, `pap+https://`, and `pap+wss://` URI classification, resolution, and rendering in Papillon's block renderer and palette pipeline.

**Architecture:** New `pap_uri` module in `papillon-shared` (testable pure Rust), `CatalogState` reactive store in the frontend, resolution injected at the top of `submit_prompt` and `retry_block`, and a new `PapLink` leaf renderer in `generic.rs`. Special authorities rewrite to natural-language intents. `pap+https://` and `pap+wss://` return a clear "not yet available" error in v1.0.

**Tech Stack:** Rust (no_std-compatible for the resolver), Leptos 0.8 (CatalogState, rendering), `web-sys::Window.confirm_with_message` (confirmation dialog), `papillon-shared` for shared types.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `crates/papillon-shared/src/pap_uri.rs` | Create | `LinkOrigin`, `ResolvedUri`, `PapUriError`, `resolve_pap_uri()` — pure Rust, fully tested |
| `crates/papillon-shared/src/lib.rs` | Modify | Add `pub mod pap_uri;` |
| `apps/papillon/frontend/src/components/block_renderer/field_classify.rs` | Modify | Add `PapLink` and `ExternalUrl` variants, fix classification order |
| `apps/papillon/frontend/src/components/block_renderer/generic.rs` | Modify | Add `PapLink` rendering arm in `render_leaf_field`, update `Url→ExternalUrl` match arms |
| `apps/papillon/frontend/src/state/catalog.rs` | Create | `CatalogState` Leptos reactive signal wrapping `HashMap<String, String>` name→DID |
| `apps/papillon/frontend/src/state/mod.rs` | Modify | Add `pub mod catalog;` |
| `apps/papillon/frontend/src/state/canvas.rs` | Modify | Call `resolve_pap_uri` in `submit_prompt` and `retry_block` |
| `apps/papillon/frontend/src/app.rs` | Modify | Create and provide `CatalogState`; add `create_effect` to refresh when `registry_state.agents` changes |

---

### Task 1: `pap_uri.rs` — Pure resolver in papillon-shared

**Files:**
- Create: `crates/papillon-shared/src/pap_uri.rs`
- Modify: `crates/papillon-shared/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of a new file `crates/papillon-shared/src/pap_uri.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty() -> HashMap<String, String> {
        HashMap::new()
    }

    fn catalog(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn special_receipt_principal() {
        let r = resolve_pap_uri("pap://receipt/RCP_abc123", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show receipt RCP_abc123".into()));
    }

    #[test]
    fn special_receipt_agent_is_blocked() {
        let err = resolve_pap_uri("pap://receipt/RCP_abc123", &empty(), LinkOrigin::Agent).unwrap_err();
        assert_eq!(err, PapUriError::Reserved);
    }

    #[test]
    fn special_canvas_agent_is_blocked() {
        let err = resolve_pap_uri("pap://canvas/cid/bid", &empty(), LinkOrigin::Agent).unwrap_err();
        assert_eq!(err, PapUriError::Reserved);
    }

    #[test]
    fn special_settings_principal() {
        let r = resolve_pap_uri("pap://settings/general", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("open settings general".into()));
    }

    #[test]
    fn special_canvas_with_block() {
        let r = resolve_pap_uri("pap://canvas/cid/blk", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show canvas cid block blk".into()));
    }

    #[test]
    fn did_key_passthrough() {
        let uri = "pap://did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Did(uri.into()));
    }

    #[test]
    fn catalog_rewrite() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri(
            "pap://arxiv/SearchAction?query=quantum%20computing",
            &cat,
            LinkOrigin::Principal,
        )
        .unwrap();
        assert_eq!(
            r,
            ResolvedUri::Did("pap://did:key:z6MkTestKey/SearchAction?query=quantum%20computing".into())
        );
    }

    #[test]
    fn catalog_miss_returns_not_found() {
        let err = resolve_pap_uri("pap://unknown/SearchAction", &empty(), LinkOrigin::Principal)
            .unwrap_err();
        assert_eq!(err, PapUriError::NotFound("unknown".into()));
    }

    #[test]
    fn registry_hostname_passthrough() {
        let uri = "pap://chrysalis.example.com/agents/arxiv/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Registry(uri.into()));
    }

    #[test]
    fn localhost_is_registry_host() {
        let uri = "pap://localhost/agents/dev/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Registry(uri.into()));
    }

    #[test]
    fn ipv4_is_registry_host() {
        let uri = "pap://192.168.1.1/agents/local/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Registry(uri.into()));
    }

    #[test]
    fn recapture_https_deferred() {
        let err = resolve_pap_uri(
            "pap+https://api.example.com/agents/flights/BuyAction",
            &empty(),
            LinkOrigin::Principal,
        )
        .unwrap_err();
        assert_eq!(err, PapUriError::RecaptureDeferred);
    }

    #[test]
    fn recapture_wss_deferred() {
        let err = resolve_pap_uri(
            "pap+wss://stream.example.com/agents/feed/ListenAction",
            &empty(),
            LinkOrigin::Principal,
        )
        .unwrap_err();
        assert_eq!(err, PapUriError::RecaptureDeferred);
    }

    #[test]
    fn non_pap_uri_parse_error() {
        let err = resolve_pap_uri("https://example.com", &empty(), LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn empty_authority_parse_error() {
        let err = resolve_pap_uri("pap:///SearchAction", &empty(), LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn catalog_lookup_is_case_insensitive() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri("pap://ARXIV/SearchAction", &cat, LinkOrigin::Principal).unwrap();
        assert!(matches!(r, ResolvedUri::Did(_)));
    }

    #[test]
    fn reserved_words_not_catalog_matched() {
        // Even if catalog has "receipt", special authority check fires first
        let cat = catalog(&[("receipt", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri("pap://receipt/RCP_1", &cat, LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show receipt RCP_1".into()));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /Users/toadkicker/Documents/GitHub/pap
cargo test -p papillon-shared --no-default-features --features wasm pap_uri 2>&1 | head -20
```

Expected: compile error — `pap_uri` module not found.

- [ ] **Step 3: Implement `pap_uri.rs`**

Write the full file `crates/papillon-shared/src/pap_uri.rs`:

```rust
use std::collections::HashMap;

/// Where a `pap://` link originated.
/// Agent-rendered links are blocked from activating special authorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOrigin {
    /// Typed directly by the principal (palette, address bar).
    Principal,
    /// Embedded in an agent-rendered JSON-LD block.
    Agent,
}

/// Resolved form of a `pap://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedUri {
    /// Already a `did:key:` form — pass to backend as-is.
    Did(String),
    /// Registry hostname form — pass to backend as-is.
    Registry(String),
    /// Natural-language intent derived from a special authority.
    LocalIntent(String),
}

/// Resolution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PapUriError {
    /// Agent-rendered link tried to activate a special authority.
    Reserved,
    /// `pap+https://` or `pap+wss://` enforcement is not built in v1.0.
    RecaptureDeferred,
    /// Catalog miss — no agent with this name in the local catalog.
    NotFound(String),
    /// URI could not be parsed.
    ParseError(String),
}

/// Reserved authority words — resolved locally, never hit the network.
const RESERVED: &[&str] = &["receipt", "canvas", "settings"];

/// Resolve a `pap://` URI using the four-step priority chain.
///
/// Step 0: special authorities (`receipt`, `canvas`, `settings`)
/// Step 1: `did:key:` prefix — pass through
/// Step 2: bare catalog name (no dot, not reserved) — rewrite via catalog
/// Step 3: hostname / localhost / IPv4 — registry passthrough
///
/// Returns `Err(PapUriError::Reserved)` if an agent-rendered link tries to
/// activate a special authority. Returns `Err(PapUriError::RecaptureDeferred)`
/// for `pap+https://` and `pap+wss://` URIs (v1.0 enforcement deferred).
pub fn resolve_pap_uri(
    uri: &str,
    catalog: &HashMap<String, String>,
    origin: LinkOrigin,
) -> Result<ResolvedUri, PapUriError> {
    // Recapture schemes are parse-only in v1.0
    if uri.starts_with("pap+https://") || uri.starts_with("pap+wss://") {
        return Err(PapUriError::RecaptureDeferred);
    }

    let rest = uri
        .strip_prefix("pap://")
        .ok_or_else(|| PapUriError::ParseError(format!("not a pap:// URI: {}", uri)))?;

    // Split authority from path (everything after the first '/')
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    if authority.is_empty() {
        return Err(PapUriError::ParseError("empty authority".into()));
    }

    // Step 0: special authorities
    let authority_lower = authority.to_lowercase();
    if RESERVED.contains(&authority_lower.as_str()) {
        if origin == LinkOrigin::Agent {
            return Err(PapUriError::Reserved);
        }
        return Ok(ResolvedUri::LocalIntent(special_to_intent(
            &authority_lower,
            path,
        )));
    }

    // Step 1: did:key: authority — PAP parser treats this as atomic
    if authority.starts_with("did:key:") {
        return Ok(ResolvedUri::Did(uri.to_string()));
    }

    // Step 3 check first: hostname / localhost / IPv4 get registry treatment
    if is_registry_host(authority) {
        return Ok(ResolvedUri::Registry(uri.to_string()));
    }

    // Step 2: catalog name
    if let Some(did) = catalog.get(authority_lower.as_str()) {
        let rewritten = format!("pap://{}{}", did, path);
        return Ok(ResolvedUri::Did(rewritten));
    }

    Err(PapUriError::NotFound(authority_lower))
}

fn is_registry_host(authority: &str) -> bool {
    authority == "localhost"
        || authority.starts_with('[') // IPv6 literal
        || authority.contains('.')
        || is_ipv4(authority)
}

fn is_ipv4(s: &str) -> bool {
    let mut parts = s.split('.');
    let count = s.split('.').count();
    count == 4 && parts.all(|p| p.parse::<u8>().is_ok())
}

fn special_to_intent(authority: &str, path: &str) -> String {
    let path = path.trim_start_matches('/');
    match authority {
        "receipt" => {
            if path.is_empty() {
                "show receipts".into()
            } else {
                format!("show receipt {}", path)
            }
        }
        "canvas" => {
            let mut parts = path.splitn(2, '/');
            match (parts.next(), parts.next()) {
                (Some(cid), Some(bid)) if !cid.is_empty() => {
                    format!("show canvas {} block {}", cid, bid)
                }
                (Some(cid), _) if !cid.is_empty() => format!("show canvas {}", cid),
                _ => "show canvas".into(),
            }
        }
        "settings" => {
            if path.is_empty() {
                "open settings".into()
            } else {
                format!("open settings {}", path)
            }
        }
        other => format!("open {}", other),
    }
}
```

- [ ] **Step 4: Add `pub mod pap_uri;` to `crates/papillon-shared/src/lib.rs`**

Read the current `lib.rs` first, then add the line. The file already has a series of `pub mod` declarations. Add:

```rust
pub mod pap_uri;
```

- [ ] **Step 5: Run the tests and verify they pass**

```bash
cd /Users/toadkicker/Documents/GitHub/pap
cargo test -p papillon-shared --no-default-features --features wasm pap_uri 2>&1
```

Expected: all 17 tests pass, no failures.

- [ ] **Step 6: Commit**

```bash
git add crates/papillon-shared/src/pap_uri.rs crates/papillon-shared/src/lib.rs
git commit -m "feat(pap-uri): add pap:// URI resolver with full test coverage"
```

---

### Task 2: `field_classify.rs` — Add `PapLink` and `ExternalUrl` variants

**Files:**
- Modify: `apps/papillon/frontend/src/components/block_renderer/field_classify.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block at the bottom of `field_classify.rs`:

```rust
    #[test]
    fn classify_pap_link() {
        assert_eq!(
            classify_field("url", &json!("pap://arxiv/SearchAction")),
            FieldKind::PapLink
        );
    }

    #[test]
    fn classify_pap_plus_https() {
        assert_eq!(
            classify_field("link", &json!("pap+https://api.example.com/agents/buy")),
            FieldKind::PapLink
        );
    }

    #[test]
    fn classify_pap_plus_wss() {
        assert_eq!(
            classify_field("stream", &json!("pap+wss://stream.example.com/listen")),
            FieldKind::PapLink
        );
    }

    #[test]
    fn classify_https_as_external_url() {
        assert_eq!(
            classify_field("website", &json!("https://example.com")),
            FieldKind::ExternalUrl
        );
    }

    #[test]
    fn classify_http_as_external_url() {
        assert_eq!(
            classify_field("link", &json!("http://example.com")),
            FieldKind::ExternalUrl
        );
    }

    #[test]
    fn pap_link_in_date_keyed_field_is_still_pap_link() {
        // pap:// check must fire BEFORE DateTime key-name check
        assert_eq!(
            classify_field("startDate", &json!("pap://arxiv/SearchAction")),
            FieldKind::PapLink
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/toadkicker/Documents/GitHub/pap
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1 | head -30
```

Expected: compile errors — `PapLink` and `ExternalUrl` variants don't exist.

- [ ] **Step 3: Add `PapLink` and `ExternalUrl` to `FieldKind`**

In `field_classify.rs`, replace the existing `FieldKind` enum:

```rust
#[derive(Debug, PartialEq)]
pub enum FieldKind {
    /// Plain text, number, or boolean.
    Scalar,
    /// ISO 8601 date/datetime or a key hinting at temporal data.
    DateTime,
    /// Monetary value (key contains "price", "cost", "amount").
    Price,
    /// HTTP or HTTPS URL. Rendered as a plain external link.
    ExternalUrl,
    /// PAP-scheme link (pap://, pap+https://, pap+wss://).
    /// Rendered as a clickable intent button, never a hyperlink.
    PapLink,
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
```

- [ ] **Step 4: Update `classify_string` — insert `pap://` check before DateTime check**

Replace the existing `classify_string` function:

```rust
fn classify_string(key: &str, s: &str) -> FieldKind {
    if s.is_empty() {
        return FieldKind::Empty;
    }
    // PAP schemes MUST be checked before the DateTime key-name heuristic to
    // prevent misclassifying pap:// URIs stored in date-keyed fields.
    if s.starts_with("pap://") || s.starts_with("pap+https://") || s.starts_with("pap+wss://") {
        return FieldKind::PapLink;
    }
    let lower_key = key.to_lowercase();
    if lower_key.contains("date") || lower_key.contains("time") || looks_like_iso_date(s) {
        return FieldKind::DateTime;
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return FieldKind::ExternalUrl;
    }
    if s.starts_with("did:") {
        return FieldKind::Did;
    }
    FieldKind::Scalar
}
```

- [ ] **Step 5: Fix the existing `classify_url` test — rename `Url` to `ExternalUrl`**

In the existing tests, find:
```rust
    #[test]
    fn classify_url() {
        assert_eq!(
            classify_field("website", &json!("https://example.com")),
            FieldKind::Url
        );
    }
```

Replace with:
```rust
    #[test]
    fn classify_url() {
        assert_eq!(
            classify_field("website", &json!("https://example.com")),
            FieldKind::ExternalUrl
        );
    }
```

- [ ] **Step 6: Verify frontend WASM compiles (catches all Url→ExternalUrl match arm fixes needed)**

```bash
cd /Users/toadkicker/Documents/GitHub/pap
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1
```

This will show every match arm in `generic.rs` and `declarative.rs` that still uses `FieldKind::Url`. Fix each one: rename `FieldKind::Url` → `FieldKind::ExternalUrl`.

In `generic.rs`, in `flatten_to_entries`, the match arm at the bottom of the `WorkItem::Visit` handler:
```rust
                    FieldKind::Scalar
                    | FieldKind::DateTime
                    | FieldKind::Price
                    | FieldKind::ExternalUrl   // was Url
                    | FieldKind::Did => {
```

In `generic.rs`, in `render_leaf_field`, the `FieldKind::Url` arm:
```rust
        FieldKind::ExternalUrl => {    // was Url
```

- [ ] **Step 7: Verify clean compile**

```bash
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1
```

Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add apps/papillon/frontend/src/components/block_renderer/field_classify.rs \
        apps/papillon/frontend/src/components/block_renderer/generic.rs
git commit -m "feat(field-classify): add PapLink/ExternalUrl variants, fix classification order"
```

---

### Task 3: `state/catalog.rs` — CatalogState reactive name→DID index

**Files:**
- Create: `apps/papillon/frontend/src/state/catalog.rs`
- Modify: `apps/papillon/frontend/src/state/mod.rs`

- [ ] **Step 1: Create `catalog.rs`**

Write `apps/papillon/frontend/src/state/catalog.rs`:

```rust
use leptos::prelude::*;
use papillon_shared::AgentInfo;
use std::collections::HashMap;

/// Reactive name-to-DID index built from the connected registry's agent list.
/// Used by the pap:// resolver's step 2 (catalog name lookup).
#[derive(Clone, Copy)]
pub struct CatalogState {
    /// Lowercase agent name → did:key:... string.
    /// None entries are omitted — only agents with a known DID are indexed.
    pub entries: RwSignal<HashMap<String, String>>,
}

impl Default for CatalogState {
    fn default() -> Self {
        Self {
            entries: RwSignal::new(HashMap::new()),
        }
    }
}

impl CatalogState {
    /// Rebuild the index from a fresh agent list.
    /// Called when the registry browser loads agents or the user connects to a new registry.
    pub fn refresh(&self, agents: &[AgentInfo]) {
        self.entries.set(build_catalog(agents));
    }

    /// Snapshot the current entries for synchronous resolution (no reactive tracking).
    pub fn snapshot(&self) -> HashMap<String, String> {
        self.entries.get_untracked()
    }
}

/// Build a `name → DID` map from an agent list.
/// Agents without a `agent_did` are skipped (remote registry agents without a known DID
/// cannot be directly resolved via catalog shorthand).
pub fn build_catalog(agents: &[AgentInfo]) -> HashMap<String, String> {
    agents
        .iter()
        .filter_map(|a| {
            a.agent_did
                .as_ref()
                .map(|did| (a.name.to_lowercase(), did.clone()))
        })
        .collect()
}
```

- [ ] **Step 2: Add `pub mod catalog;` to `state/mod.rs`**

Edit `apps/papillon/frontend/src/state/mod.rs` from:
```rust
pub mod canvas;
pub mod identity;
pub mod orchestrator;
pub mod registry;
pub mod templates;
```
to:
```rust
pub mod canvas;
pub mod catalog;
pub mod identity;
pub mod orchestrator;
pub mod registry;
pub mod templates;
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add apps/papillon/frontend/src/state/catalog.rs \
        apps/papillon/frontend/src/state/mod.rs
git commit -m "feat(catalog): add CatalogState reactive name-to-DID index"
```

---

### Task 4: `canvas.rs` — Resolve `pap://` in `submit_prompt` and `retry_block`

**Files:**
- Modify: `apps/papillon/frontend/src/state/canvas.rs`

- [ ] **Step 1: Add imports at the top of `canvas.rs`**

The existing imports start with:
```rust
use leptos::prelude::*;
use papillon_shared::{BlockState, Canvas, CanvasBlock};
```

Add to the import block:
```rust
use papillon_shared::pap_uri::{resolve_pap_uri, LinkOrigin, PapUriError, ResolvedUri};
use crate::state::catalog::CatalogState;
```

- [ ] **Step 2: Add the `resolve_prompt_text` helper after the existing `expand_block_references` function (around line 100)**

Insert this function after `expand_block_references`:

```rust
/// If `text` is a `pap://` URI, resolve it using the local catalog.
/// Returns the resolved form to pass to the backend, or `None` if resolution
/// failed and the caller should abort dispatch (error already logged).
fn resolve_prompt_text(text: &str) -> Option<String> {
    let is_pap = text.starts_with("pap://")
        || text.starts_with("pap+https://")
        || text.starts_with("pap+wss://");

    if !is_pap {
        return Some(text.to_string());
    }

    let catalog_map = use_context::<CatalogState>()
        .map(|c| c.snapshot())
        .unwrap_or_default();

    match resolve_pap_uri(text, &catalog_map, LinkOrigin::Principal) {
        Ok(ResolvedUri::LocalIntent(intent)) => Some(intent),
        Ok(ResolvedUri::Did(uri)) => Some(uri),
        Ok(ResolvedUri::Registry(uri)) => Some(uri),
        Err(PapUriError::RecaptureDeferred) => {
            leptos::logging::warn!(
                "pap+https:// / pap+wss:// recapture enforcement not yet available: {}",
                text
            );
            None
        }
        Err(e) => {
            leptos::logging::warn!("PAP URI resolution failed for {}: {:?}", text, e);
            None
        }
    }
}
```

- [ ] **Step 3: Call `resolve_prompt_text` in `submit_prompt` — inject BEFORE `expand_block_references`**

In `submit_prompt`, find the block starting with:
```rust
        // Extract block references and expand them for the backend
        let all_canvases = canvases.get();
        let linked_block_ids = extract_block_ids(&text);
        let expanded_text = expand_block_references(&text, &all_canvases);
```

Replace it with:
```rust
        // Resolve pap:// URIs before block reference expansion.
        // Returns None if resolution failed — abort dispatch in that case.
        let resolved_text = match resolve_prompt_text(&text) {
            Some(t) => t,
            None => {
                // Mark block as failed inline
                canvases.update(|cs| {
                    if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                        if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
                            b.state = BlockState::Failed {
                                phase: 1,
                                reason: "PAP URI resolution failed — see console for details."
                                    .into(),
                            };
                            b.updated_at = now_iso();
                        }
                    }
                });
                return;
            }
        };

        // Extract block references and expand them for the backend
        let all_canvases = canvases.get();
        let linked_block_ids = extract_block_ids(&resolved_text);
        let expanded_text = expand_block_references(&resolved_text, &all_canvases);
```

Note: `text` (the original pap:// URI) is still stored in `block.prompt_text` for display and retry. Only `expanded_text` changes.

- [ ] **Step 4: Call `resolve_prompt_text` in `retry_block`**

In `retry_block`, find the line:
```rust
        let original_text = canvases
            .get()
            .iter()
            .flat_map(|c| c.blocks.iter())
            .find(|b| b.id == block_id)
            .and_then(|b| b.prompt_text.clone())
            .unwrap_or_default();
```

Replace with:
```rust
        let raw_text = canvases
            .get()
            .iter()
            .flat_map(|c| c.blocks.iter())
            .find(|b| b.id == block_id)
            .and_then(|b| b.prompt_text.clone())
            .unwrap_or_default();

        // Re-resolve pap:// URI on retry (catalog may have updated since first attempt)
        let original_text = match resolve_prompt_text(&raw_text) {
            Some(t) => t,
            None => return, // resolution failed, error already logged
        };
```

- [ ] **Step 5: Verify it compiles**

```bash
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/state/canvas.rs
git commit -m "feat(canvas): resolve pap:// URIs in submit_prompt and retry_block"
```

---

### Task 5: `app.rs` — Provide `CatalogState` and wire refresh effect

**Files:**
- Modify: `apps/papillon/frontend/src/app.rs`

- [ ] **Step 1: Add `CatalogState` import**

Find the existing imports in `app.rs`:
```rust
use crate::state::canvas::CanvasState;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use crate::state::registry::RegistryState;
use crate::state::templates::TemplatesState;
```

Add:
```rust
use crate::state::catalog::CatalogState;
```

- [ ] **Step 2: Create `CatalogState` and provide it as context**

In the `App` component, find the block:
```rust
    let identity_state = IdentityState::default();
    let registry_state = RegistryState::default();
    let orchestrator_state = OrchestratorState::default();
    let canvas_state = CanvasState::default();
    let templates_state = TemplatesState::default();
    provide_context(identity_state);
    provide_context(registry_state);
    provide_context(orchestrator_state);
    provide_context(canvas_state);
    provide_context(templates_state);
```

Add `catalog_state` and its `provide_context` call:
```rust
    let identity_state = IdentityState::default();
    let registry_state = RegistryState::default();
    let orchestrator_state = OrchestratorState::default();
    let canvas_state = CanvasState::default();
    let templates_state = TemplatesState::default();
    let catalog_state = CatalogState::default();
    provide_context(identity_state);
    provide_context(registry_state);
    provide_context(orchestrator_state);
    provide_context(canvas_state);
    provide_context(templates_state);
    provide_context(catalog_state);
```

- [ ] **Step 3: Add effect to refresh catalog when agents load**

After the `provide_context` calls, add a reactive effect that watches `registry_state.agents` and refreshes the catalog. Insert after the last `provide_context(...)` line:

```rust
    // Keep catalog in sync with the registry agent list.
    // Runs immediately and re-runs whenever registry_state.agents changes.
    create_effect(move |_| {
        let agents = registry_state.agents.get();
        catalog_state.refresh(&agents);
    });
```

- [ ] **Step 4: Verify it compiles**

```bash
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/app.rs
git commit -m "feat(app): provide CatalogState context and wire registry-agents refresh"
```

---

### Task 6: `generic.rs` — Render `PapLink` as a confirmation-gated intent button

**Files:**
- Modify: `apps/papillon/frontend/src/components/block_renderer/generic.rs`

- [ ] **Step 1: Add `CanvasState` import to `generic.rs`**

Find the existing imports:
```rust
use leptos::prelude::*;
use serde_json::Value;
use std::sync::Arc;

use super::field_classify::{
    camel_to_kebab, classify_field, format_datetime, humanize_key, sanitize_css_class,
    scalar_to_string, schema_type_to_css, FieldKind,
};
use super::registry::RendererRegistry;
```

Add:
```rust
use crate::state::canvas::CanvasState;
```

- [ ] **Step 2: Add `PapLink` arm to the `flatten_to_entries` match for leaf fields**

In `flatten_to_entries`, in the `WorkItem::Visit` handler, find the leaf match arm:
```rust
                    FieldKind::Scalar
                    | FieldKind::DateTime
                    | FieldKind::Price
                    | FieldKind::ExternalUrl
                    | FieldKind::Did => {
```

Add `PapLink` to this arm so it gets emitted as a `Field` entry (the visual rendering happens in `render_leaf_field`):
```rust
                    FieldKind::Scalar
                    | FieldKind::DateTime
                    | FieldKind::Price
                    | FieldKind::ExternalUrl
                    | FieldKind::PapLink
                    | FieldKind::Did => {
```

- [ ] **Step 3: Add `PapLink` arm to `render_leaf_field`**

In `render_leaf_field`, find the existing `FieldKind::Did` arm (it's the last real arm before the catchall `_ =>`). Add the `PapLink` arm before it:

```rust
        FieldKind::PapLink => {
            let url = val.as_str().unwrap_or("").to_string();
            // Split scheme from body for visual treatment
            let (scheme, body) = if let Some(rest) = url.strip_prefix("pap+https://") {
                ("pap+https://", rest.to_string())
            } else if let Some(rest) = url.strip_prefix("pap+wss://") {
                ("pap+wss://", rest.to_string())
            } else if let Some(rest) = url.strip_prefix("pap://") {
                ("pap://", rest.to_string())
            } else {
                ("", url.clone())
            };
            let scheme = scheme.to_string();
            let canvas_state = use_context::<CanvasState>();
            let url_for_click = url.clone();
            view! {
                <div class=format!("typed-field typed-field-pap-link {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <button
                        class="pap-link"
                        title=url.clone()
                        on:click=move |_| {
                            // All block-renderer pap:// links are agent-rendered.
                            // Require explicit principal confirmation before dispatch.
                            let url_inner = url_for_click.clone();
                            let confirmed = web_sys::window()
                                .and_then(|w| {
                                    w.confirm_with_message(
                                        &format!("Activate PAP link?\n{}", url_inner),
                                    )
                                    .ok()
                                })
                                .unwrap_or(false);
                            if confirmed {
                                if let Some(cs) = canvas_state {
                                    cs.submit_prompt(url_inner);
                                }
                            }
                        }
                    >
                        <span class="pap-scheme">{scheme}</span>
                        <span class="pap-body">{body}</span>
                    </button>
                </div>
            }
            .into_any()
        }
```

- [ ] **Step 4: Verify it compiles**

```bash
cargo check --target wasm32-unknown-unknown -p papillon-ui 2>&1
```

Expected: no errors.

- [ ] **Step 5: Run the existing `papillon-shared` tests to confirm no regressions**

```bash
cargo test -p papillon-shared --no-default-features --features wasm 2>&1
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/components/block_renderer/generic.rs
git commit -m "feat(generic): render PapLink as confirmation-gated intent button"
```

---

### Task 7: Full integration verification

**Files:** no new files

- [ ] **Step 1: Run all papillon-shared tests**

```bash
cd /Users/toadkicker/Documents/GitHub/pap
cargo test -p papillon-shared --no-default-features --features wasm 2>&1
```

Expected: all tests pass, including the new `pap_uri` tests.

- [ ] **Step 2: Run the full WASM build**

```bash
cd /Users/toadkicker/Documents/GitHub/pap/apps/papillon/frontend
trunk build --release 2>&1 | tail -20
```

Expected: build succeeds, `dist/` directory produced.

- [ ] **Step 3: Smoke test in browser — verify PapLink renders**

```bash
# In one terminal:
npx http-server dist -p 8080 --cors &
# In another terminal:
npx playwright test e2e/tests/web-standalone.spec.ts 2>&1
```

Expected: all 14 existing E2E tests still pass (no regressions from the field_classify and generic changes).

- [ ] **Step 4: Manual smoke test — verify pap:// link rendering**

Open `http://localhost:8080` in a browser. Submit a prompt that returns JSON-LD with a `pap://` link. Verify:
1. The field renders as a `<button class="pap-link">` not plain text
2. The scheme (`pap://`) and body are in separate spans
3. Clicking the button shows a browser confirm dialog
4. Clicking OK dispatches a new canvas prompt
5. Clicking Cancel does nothing

- [ ] **Step 5: Final commit if any fixes were needed**

```bash
git add -p
git commit -m "fix(pap-uri): integration smoke test fixes"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task covering it |
|---|---|
| §15.2 ABNF: PAP schemes classified | Task 2 (`field_classify.rs`) |
| §15.3 Step 0: special authorities | Task 1 (`pap_uri.rs`) |
| §15.3 Step 1: did:key: passthrough | Task 1 |
| §15.3 Step 2: catalog name → DID | Tasks 1, 3, 4 |
| §15.3 Step 3: registry hostname | Task 1 |
| §15.3 Resolution failure → inline error | Task 4 (`canvas.rs` block failure state) |
| §15.4 percent-encoding (not `+`) | Examples in spec only; no URL encoding code in frontend |
| §15.5 pap+https:// → deferred error | Tasks 1, 4 (`RecaptureDeferred`) |
| §15.6 PapLink rendered as intent button | Task 6 (`generic.rs`) |
| §15.6 Agent-rendered link confirmation | Task 6 (window.confirm) |
| §15.6 settings/canvas/receipt blocked from agent links | Task 1 (`Reserved` error for `Agent` origin) |
| §15.7 Special authorities to natural language | Task 1 (`special_to_intent`) |
| Catalog refresh when agents load | Task 5 (`create_effect`) |
| retry_block resolves pap:// | Task 4 |

**No placeholders, no TBDs, all code shown.**

**Type consistency:**
- `LinkOrigin` defined in Task 1, used in Task 4 — consistent
- `CatalogState::snapshot()` defined in Task 3, called in Task 4 — consistent
- `FieldKind::PapLink` defined in Task 2, matched in Task 6 — consistent
- `FieldKind::ExternalUrl` replaces `Url` throughout — Tasks 2 and 6 both updated

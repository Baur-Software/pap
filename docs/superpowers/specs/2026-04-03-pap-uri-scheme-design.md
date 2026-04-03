# PAP URI Scheme Design

> **For agentic workers:** Use superpowers:writing-plans to implement this spec.

**Goal:** Define the `pap://`, `pap+https://`, and `pap+wss://` URI scheme, implement resolution in Papillon's palette input, and wire `pap://` links in the block renderer.

**Architecture:** Three-tier authority resolution (DID → catalog name → registry hostname) feeding into the existing `submit_prompt` intent pipeline. No new navigation primitive — every `pap://` activation is intent.

**Tech Stack:** Rust/Leptos frontend (`field_classify.rs`, `canvas.rs`, `state/canvas.rs`), spec in `docs/specification.md` (Section 15, already written).

---

## What We're Building

### The Three Scheme Variants

| Scheme | When to use |
|---|---|
| `pap://` | PAP-native agents. Client negotiates transport. |
| `pap+https://` | Existing HTTPS endpoints brought under PAP mandate scope. |
| `pap+wss://` | Existing WebSocket endpoints brought under PAP mandate scope. |

`pap+https://` is the recapture scheme — it applies PAP's mandate enforcement, selective disclosure, and co-signed receipts to any HTTPS endpoint whether or not that endpoint knows about PAP. The principal's client enforces the protocol locally.

**v1.0 scope:** `pap+https://` and `pap+wss://` are parsed and classified in v1.0 but full mandate enforcement is deferred. v1.0 renders them as intent links and rejects activation with a clear "recapture enforcement not yet available" error. They are NOT silently downgraded to plain HTTPS requests.

### URL Grammar

```
pap://arxiv/SearchAction?query=quantum%20computing          ; catalog shorthand
pap://did:key:z6Mk.../SearchAction                          ; direct P2P
pap://chrysalis.example.com/agents/arxiv/SearchAction       ; registry (slug in path)
pap+https://api.example.com/agents/flights/BuyAction        ; recapture HTTPS
pap://receipt/RCP_abc123                                    ; special authority
pap://canvas/{canvas-id}/{block-id}                         ; block deep-link
```

Authority is always the host (or DID, or catalog name). The `/agents/{slug}` segment is in the path for registry URIs, not part of the authority. Query values are percent-encoded per RFC 3986; `+` is not a space encoding.

### Resolution Priority Chain

0. `receipt` / `canvas` / `settings` → local special authority, no network lookup
1. `did:key:` prefix → DID Document endpoint discovery, direct handshake
2. No `.` in authority, not a reserved word → catalog name lookup (case-insensitive `name` match), rewrite to DID, go to 1
3. `.` in authority, or `localhost`, or IP literal → registry hostname, query `/agents/{slug}/`, initiate handshake

If all steps fail, render an inline error in place of the link. Never silently fall back.

### What "Intent" Means Here

Every `pap://` activation feeds into `submit_prompt`. There is no secondary navigation system. A receipt deep-link becomes "show me receipt RCP_abc123". A block deep-link becomes "show me block {id} in canvas {id}". The canvas handles it.

---

## Components

### 1. `field_classify.rs` — New `FieldKind` variants

Add `PapLink` and `ExternalUrl` (rename current `Url`):

```rust
pub enum FieldKind {
    // existing...
    ExternalUrl,   // http:// or https://
    PapLink,       // pap://, pap+https://, pap+wss://
    // ...
}
```

In `classify_string`, match `pap://`, `pap+https://`, `pap+wss://` **before** the existing `https://` check **and before** the DateTime check. The `pap://` prefix cannot be mistaken for a date, but ordering discipline prevents future regressions.

### 2. `generic.rs` — Render `PapLink` as clickable intent

In `render_stream`, when `FieldKind::PapLink`:
- Render as `<button class="pap-link">` (not `<a href>`)
- `on:click` calls `canvas_state.submit_prompt(url)`
- Display the URL with the scheme visually distinct (`.pap-scheme` span + `.pap-body` span)
- For agent-rendered links: show a provenance badge naming the source agent, require explicit confirmation before dispatch

When `FieldKind::ExternalUrl`:
- Render as before (plain `<a href>`)
- Do NOT add an "open via PAP" affordance — that creates false recapture assurance before enforcement is built

### 3. `state/canvas.rs` — Resolution in `submit_prompt`

At the top of `submit_prompt`, before the existing intent dispatch:

```rust
let text = if text.starts_with("pap://") || text.starts_with("pap+https://") || text.starts_with("pap+wss://") {
    resolve_pap_uri(&text, &catalog)?
} else {
    text
};
```

`resolve_pap_uri` signature:

```rust
pub fn resolve_pap_uri(uri: &str, catalog: &CatalogState) -> Result<ResolvedUri, PapUriError>

pub enum ResolvedUri {
    Did(String),          // rewritten to did:key: form
    Registry(String),     // hostname + path form, passthrough
    LocalIntent(String),  // natural-language string for special authorities
}

pub enum PapUriError {
    Reserved,             // agent tried to use settings/canvas/receipt
    RecaptureDeferred,    // pap+https:// enforcement not built yet
    NotFound(String),     // catalog miss or registry 404
    ParseError(String),
}
```

`resolve_pap_uri` applies the four-step chain (steps 0–3). Special authorities (`receipt/`, `canvas/`, `settings/`) are rewritten to natural-language intent strings the existing dispatch already handles.

The `retry_block` path MUST also call `resolve_pap_uri` if the retry input is a `pap://` URI. Do not add the resolution call only at the top-level `submit_prompt` entry point.

### 4. `catalog.rs` (frontend) — Catalog name index

A lightweight `name → DID` map built from the agent list at startup. Lives in `CatalogState` (new struct, owned by `AppState`). Used by step 2 of the resolution chain.

```rust
pub struct CatalogState {
    pub entries: HashMap<String, String>,  // lowercase name → did:key:...
}
```

Built at startup from the same agent list that populates the registry browser. Updated when the user connects to a new registry.

---

## Data Flow

```
User types / clicks pap:// link
        ↓
submit_prompt(uri)
        ↓
resolve_pap_uri()
  ├─ special authority → natural language intent (no network)
  ├─ did:key: → passthrough
  ├─ bare name → catalog lookup → rewrite to did:key:
  ├─ hostname/IP/localhost → registry slug → passthrough
  └─ error → inline error render, no dispatch
        ↓
Existing intent dispatch (Tauri IPC or WebService)
        ↓
Agent executes, returns JSON-LD
        ↓
BlockRenderer → render_typed_content
        ↓
FieldKind::PapLink → clickable button (with provenance badge if agent-rendered)
  → principal confirmation → submit_prompt (cycle)
```

---

## Security

- Agent-rendered `pap://` links MUST show a provenance badge and require confirmation.
- Agent-rendered links MUST NOT activate `settings`, `canvas`, or `receipt` — `resolve_pap_uri` returns `PapUriError::Reserved` for these when called from an agent context. The caller passes an `origin: LinkOrigin` parameter to enforce this.
- `pap+https://` activation in v1.0 returns `PapUriError::RecaptureDeferred` and renders a clear error. No silent HTTPS fallback.

---

## What's Not in Scope

- `pap+https://` recapture enforcement (mandate wrapping around HTTPS requests) — backend concern for a later milestone
- Browser extension `pap://` protocol handler registration — separate deliverable
- IANA URI scheme registration — post-v1.0
- "Open via PAP" affordance on external URLs — deferred with enforcement layer
- `pap+wss://` streaming lifecycle (chunked frames, reconnect) — v1.1

The palette routing and link rendering are the v1.0 pieces. Recapture enforcement ships when the mandate enforcement layer is complete.

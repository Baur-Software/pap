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

### URL Grammar

```
pap://arxiv/SearchAction?query=quantum+computing          ; catalog shorthand
pap://did:key:z6Mk.../SearchAction                        ; direct P2P
pap://chrysalis.example.com/agents/arxiv/SearchAction     ; registry
pap+https://api.example.com/agents/flights/BuyAction      ; recapture HTTPS
pap://receipt/RCP_abc123                                  ; special authority
pap://canvas/{canvas-id}/{block-id}                       ; block deep-link
```

### Resolution Priority Chain

1. `did:key:` prefix → DID Document endpoint discovery, direct handshake
2. No `.` in authority → catalog name lookup (case-insensitive `name` match), rewrite to DID, go to 1
3. `.` in authority → registry hostname, query `/agents/{slug}/`, initiate handshake

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

In `classify_string`, match `pap://`, `pap+https://`, `pap+wss://` before the existing `https://` check.

### 2. `generic.rs` — Render `PapLink` as clickable intent

In `render_stream`, when `FieldKind::PapLink`:
- Render as `<button class="pap-link">` (not `<a href>`)
- `on:click` calls `canvas_state.submit_prompt(url)`
- Display the URL with the scheme visually distinct (`.pap-scheme` span + `.pap-body` span)

When `FieldKind::ExternalUrl`:
- Render as before, but add a small "open via PAP" affordance that rewrites to `pap+https://` equivalent

### 3. `state/canvas.rs` — Resolution in `submit_prompt`

At the top of `submit_prompt`, before the existing intent dispatch:

```rust
let text = if text.starts_with("pap://") || text.starts_with("pap+https://") || text.starts_with("pap+wss://") {
    resolve_pap_uri(&text, &catalog)
} else {
    text
};
```

`resolve_pap_uri` applies the three-step chain and returns either the original URI (if it's already a DID or registry form) or a rewritten form the backend understands. Special authorities (`receipt/`, `canvas/`, `settings/`) are rewritten to natural-language intent strings the existing dispatch already handles.

### 4. `catalog.rs` (frontend) — Catalog name index

A lightweight name→DID map built from the agent list at startup. Used by step 2 of the resolution chain. Lives in `RegistryState` or a new `CatalogState`.

---

## Data Flow

```
User types / clicks pap:// link
        ↓
submit_prompt(uri)
        ↓
resolve_pap_uri()
  ├─ did:key: → passthrough
  ├─ bare name → catalog lookup → rewrite to did:key:
  ├─ hostname → registry slug → passthrough
  └─ special authority → natural language intent
        ↓
Existing intent dispatch (Tauri IPC or WebService)
        ↓
Agent executes, returns JSON-LD
        ↓
BlockRenderer → render_typed_content
        ↓
FieldKind::PapLink → clickable button → submit_prompt (cycle)
```

---

## What's Not in Scope

- `pap+https://` recapture enforcement (mandate wrapping around HTTPS requests) — that's a backend concern for a later milestone
- Browser extension `pap://` protocol handler registration — separate deliverable
- IANA URI scheme registration — post-v1.0

The palette routing and link rendering are the v1.0 pieces. Recapture enforcement is the mechanism that makes `pap+https://` meaningful at the protocol level — it ships when the mandate enforcement layer is complete.

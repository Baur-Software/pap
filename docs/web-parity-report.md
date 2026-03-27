# Web Build Feature Parity Report

**Issue**: #71 — Validate Papillon web build feature parity with native
**Date**: 2026-03-24
**Branch**: `feat/eab4-validate-papilli`

## Executive Summary

The web build compiles and serves correctly, but **all five audited features are non-functional in standalone web mode**. The root cause is architectural: the Leptos frontend calls every backend operation through `bridge::invoke()` (Tauri IPC), which returns `Err("Tauri IPC not available")` when running outside the Tauri shell. The database abstraction layer (`papillon-shared`) has working WASM implementations, but the frontend never uses them directly.

| Feature | Native | Web (in Tauri) | Web (Standalone) | Gap Severity |
|---------|--------|----------------|------------------|-------------|
| Agent Discovery UI | Full | Full | **Broken** | Critical |
| Template CRUD | Full | Full | **Broken** | High |
| Profile Isolation | Full | Full | **Broken** | Critical |
| 6-Phase PAP Handshake | Full | Full | **Broken** | Critical |
| Settings Persistence | Full | Full | **Broken** | High |

## Architecture Context

```
Native build:
  Leptos WASM → bridge.rs → Tauri IPC → Rust backend (38+ commands)
                                            ├── handshake.rs (6-phase PAP)
                                            ├── profiles_db.rs (SQLite)
                                            ├── commands/templates.rs
                                            ├── discovery.rs (LAN peers)
                                            └── inference.rs (Candle LLM)

Standalone web build:
  Leptos WASM → bridge.rs → window.__TAURI__ → ❌ undefined
                    │
                    └── tauri_available() returns false
                        Every invoke() returns Err("Tauri IPC not available")
```

The frontend has consistent `if !bridge::tauri_available() { return; }` guards in `app.rs` startup Effects (lines 39, 73, 132), which means **no state loads at all** in standalone web.

## Feature-by-Feature Analysis

### 1. Agent Discovery UI — CRITICAL

**Native behavior**: Registry browser connects to `pap://` URLs via `sync_agents` and `search_agents` commands. Agent cards display capabilities, disclosure requirements, and returns. Peer discovery scans LAN.

**Web behavior**: `RegistryBrowser` component renders identically. When user clicks "Sync", `bridge::invoke("sync_agents", ...)` fails. Error is caught and displayed as "Could not reach registry — backend unavailable." (`browser.rs:76-82`).

**Root cause**: No web-native registry client. The `pap-federation` crate is not compiled into the WASM frontend. Registry protocol requires HTTP/TLS which the browser could handle via `fetch()`, but no implementation exists.

**What works**: UI layout, action filter input, agent card rendering (given mock data). The reactive state layer (`RegistryState`) is sound.

### 2. Template CRUD — HIGH

**Native behavior**: Templates stored in SQLite. Full CRUD via 7 IPC commands: `get_global_templates`, `get_profile_templates`, `create_template`, `update_template`, `delete_template`, `export_templates`, `import_templates`.

**Web behavior**: The `WasmDatabase` has complete in-memory template CRUD (`wasm.rs:259-338`). `IndexedDbDatabase` wraps it with LocalStorage persistence (`indexed_db.rs:204-226`). **BUT** — the frontend's `TemplatesTab` goes through `bridge::invoke()` for all operations, bypassing the WASM database entirely.

**Root cause**: Frontend hardcoded to Tauri IPC path. Needs a service abstraction that dispatches to either IPC (in Tauri) or direct WASM DB calls (standalone).

**What works**: Database layer fully implements `DatabaseOps` trait. Template validation (`TemplateConfig::validate()`) is in shared types. UI components render.

### 3. Profile Isolation — CRITICAL

**Native behavior**: Separate `profiles.db` SQLite database. Profile CRUD (list, create, switch, rename, delete). Profile switching resets all scoped state, regenerates identity via `PrincipalKeypair`. Constraints enforced: can't delete active profile or last profile.

**Web behavior**: `IdentityState` has all the correct signals (`profiles`, `current_profile_id`, `profiles_loading`). `app.rs` startup Effect loads profiles via `bridge::invoke_no_args("list_profiles")`, but the guard `if !bridge::tauri_available() { return; }` prevents this from executing. Result: **empty profile list, no identity, no DID**.

**Root cause**: Two missing capabilities:
1. **No web-native identity generation** — `ed25519-dalek` and `pap-did::PrincipalKeypair` are not compiled into WASM frontend. The web build cannot generate a DID keypair.
2. **No web-native profile storage** — Profile metadata is stored in a separate SQLite DB (`profiles_db.rs`), not in `papillon-shared`'s `DatabaseOps` trait. No WASM equivalent exists.

**What works**: Profile UI components render. State reset on DID change (`app.rs:87-128`) is correctly implemented. `IdentityState` struct is platform-agnostic.

### 4. 6-Phase PAP Handshake — CRITICAL

**Native behavior**: Full handshake executor in `src/handshake.rs` (280 lines). Uses `ed25519-dalek` signing, `pap-core` mandate/receipt/session, `pap-did` keypair generation, `pap-transport::AgentHandler` trait. Phase 4 uses `tokio::task::spawn_blocking` for agent execution.

**Web behavior**: Canvas submits prompts via `bridge::invoke("canvas_prompt", ...)` (`canvas.rs:141`). The optimistic "Resolving" block appears immediately but transitions to `Failed { phase: 1, reason: "Tauri IPC not available" }`.

**Root cause**: The handshake executor is native-only. Core protocol crates (`pap-core`, `pap-did`, `pap-credential`, `pap-transport`) are **not** in the WASM frontend's dependency tree. A web-native handshake executor would need:
1. Protocol crates compiled to WASM (feasible — they're pure Rust)
2. `ed25519-dalek` WASM support (available via `getrandom/js` feature)
3. Agent communication via `fetch()` instead of local handlers
4. Async execution (no `spawn_blocking` in WASM — use `wasm-bindgen-futures`)

**What works**: Canvas UI, block rendering, block state machine (`Resolving → Resolved | Failed`), optimistic updates, semantic block grouping. The `pap-wasm` crate exists as a JS SDK but is not used by the Leptos frontend.

### 5. Settings Persistence — HIGH

**Native behavior**: `tauri-plugin-store` for KV persistence. `OrchestratorConfig` saved/loaded via `configure_orchestrator` and `get_orchestrator_status` commands. Config includes LLM provider selection.

**Web behavior**: `IndexedDbDatabase` has `get_setting`/`set_setting` backed by LocalStorage (`indexed_db.rs:174-182`). BUT the `GeneralTab` saves via `bridge::invoke("configure_orchestrator", ...)`. Fails with "Could not save settings — backend unavailable." (`settings.rs:164-166`).

**Root cause**: Same as templates — frontend hardcoded to IPC. The persistence layer exists but isn't wired up.

**What works**: Settings UI renders completely (LLM provider selection, model picker, all form fields). `OrchestratorConfig` type is in shared crate.

## Additional Gaps

| Gap | Severity | Notes |
|-----|----------|-------|
| On-device LLM inference | Medium | Uses Candle (native). No WASM inference path. |
| Federation server | Medium | Spawns TLS server thread — impossible in browser. |
| LAN peer discovery | Low | OS-level network scanning — no browser API. |
| Tauri event listener | High | Block updates stream via Tauri events (`block_created`, `block_updated`). No web equivalent (could use WebSocket/SSE). |
| Model download | Low | File-system download from HuggingFace — use browser download/IndexedDB. |

## CI Gap

The current `web-build.yml` workflow:
- Builds WASM with `trunk build --release` ✅
- Checks compilation with `cargo build --target wasm32-unknown-unknown` ✅
- Verifies HTTP serving with `curl` ✅

**Missing from CI**:
- No clippy for WASM target
- No `wasm-pack test` for `papillon-shared` WASM backend
- No Playwright e2e for the web build (only verifies index.html is served)

## Recommendations

### Immediate (this PR)
1. **Add web-specific CI jobs**: WASM clippy, wasm-pack test, basic Playwright smoke test
2. **File follow-up issues** for each gap area

### Short-term (follow-up issues)
1. **Service abstraction layer**: Create a `PapillonService` trait dispatching to IPC or WASM DB
2. **Web-native identity**: Compile `pap-did` to WASM, generate keypairs in browser
3. **Web-native templates**: Wire `IndexedDbDatabase` template ops directly into frontend

### Medium-term
1. **WASM handshake executor**: Compile protocol crates to WASM, replace `spawn_blocking` with async
2. **WebSocket transport**: Replace Tauri events with WebSocket for block streaming
3. **Web-native registry client**: HTTP fetch-based registry browsing

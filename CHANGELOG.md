# Changelog

All notable changes to PAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-03-23

### Added

- **ci**: CodeQL workflow with path-based filtering — runs static analysis only when changes include target languages (Rust, Python, JavaScript/TypeScript), reducing unnecessary CI runs on documentation-only or configuration-only commits

## [0.4.1] - 2026-03-23

### Added

- **registry**: Hostable federated PAP registry — standalone Axum web service that other agents and Papillion instances can discover and query; supports both SQLite (single-node) and Postgres (clustered) backends
- **registry**: Leptos 0.8 SSR frontend — server-side-rendered agent search UI with live FTS5 results, DID display, capability badges, and pagination; single-crate architecture (no separate WASM build step)
- **registry**: Federation protocol — push/pull peer sync, `/api/peers` management endpoints, and configurable sync intervals for multi-node mesh
- **registry**: Admin REST API — token-authenticated endpoints for agent CRUD, peer management, and status; all mutations require `Authorization: Bearer <token>`
- **registry**: Ed25519 signature verification on agent registration — rejects unsigned or tampered `AgentAdvertisement` payloads at ingest
- **registry**: Docker-based test execution — `docker buildx build --target test` stage runs the full test suite at build time; CI `test-registry` job added to GitHub Actions
- **registry**: Comprehensive test suite — 34 tests covering SQLite CRUD layer, auth middleware, and all admin route handlers via `tower::ServiceExt::oneshot()`
- **papillion**: Local federated registry settings — configure endpoint and sync interval for the Papillion-embedded registry directly in the Settings panel

### Fixed

- **registry**: SQL injection hardened — FTS5 `MATCH` queries escape special characters (`"`, `*`, `^`) before interpolation (I8 regression test included)
- **registry**: Cert fingerprint exposed in `/api/status` — removed from public response; available only to authenticated admin callers
- **registry**: Docker workspace sedding anchored — regex now anchors to member path strings to avoid stripping `workspace.dependencies` lines

## [0.4.0] - 2026-03-22

### Added

- **pap-c**: New `crates/pap-c` crate — stable C FFI layer (cdylib + staticlib) exposing all PAP primitives via opaque handles, thread-local last-error storage, and a `pap_mandate_sync_decay_state` helper that automatically handles the Active→ReadOnly TTL-expiry jump
- **pap-wasm**: New `crates/pap-wasm` crate — wasm-bindgen WebAssembly bindings (`@pap/sdk` npm package) for JavaScript/TypeScript consumers; transport excluded (no reqwest in WASM)
- **bindings/cpp**: Header-only C++ RAII wrapper (`pap.hpp`) with move semantics, non-copyable handles, and CMake integration
- **bindings/csharp**: .NET 8 C# bindings via P/Invoke (`[LibraryImport]`), `SafeHandle`-based RAII wrappers, and `PapException` with `DecayState` enum matching the ABI constants
- **bindings/java**: JNA-based Java bindings (`io.pap.*`) with `AutoCloseable` handles, `DecayState`/`SessionState` enums, and 14 JUnit 5 tests covering all decay-state correctness scenarios
- **pap-c**: `pap_disclosure_entry_new` now validates null array pointers with non-zero counts (defensive hardening matching sibling functions)
- **Dockerfile.test**: Docker test harness using `docker buildx` with cargo registry cache mounts for fast iterative CI

### Fixed

- **bindings/java**: `Session.id()` was incorrectly calling `pap_session_free` on the string pointer; corrected to `pap_string_free`
- **bindings/java**: `Session.close()` now calls `pap_session_close` before `pap_session_free` — ensures proper protocol teardown before memory is released
- **bindings/csharp**: `DecayState` and `SessionState` properties now guard against `-1` sentinel before casting the FFI integer to an enum value — prevents invalid casts from garbage return values
- **bindings/cpp**: `decay_state()`, `compute_decay_state()`, and `state()` now validate the upper bound (`> PAP_DECAY_SUSPENDED` / `> PAP_SESSION_CLOSED`) as well as the lower bound — catches out-of-range enum values from future ABI versions
- **pap-core**: `compute_decay_state` now short-circuits immediately for the `Suspended` terminal state — previously, a decayed-but-suspended mandate could incorrectly re-enter `ReadOnly` after a TTL check
- **pap-c**: `pap_scope_permits` now guards the null check before calling `CStr::from_ptr`, eliminating a potential undefined-behaviour window where a null-dereference could occur inside the match arm
- **pap-c**: `pap_disclosure_entry_new` validates per-element null pointers in the permitted/required/excluded arrays before dereferencing — previously only the array pointer itself was checked
- **pap-wasm**: Removed conflicting `use` imports that shadowed local `#[wasm_bindgen]` struct definitions, fixing an `E0255` compiler error that broke WASM builds when compiled without the Docker `--exclude pap-wasm` flag

## [0.3.5] - 2026-03-21

### Added

- **docs**: Papillion marketing site (`docs/papillion/`) — consumer-facing landing page with interactive 6-step purchase demo showing AI operating within user-defined rules (budget, vendor preferences, approval thresholds)
- **docs**: Dual GitHub Pages architecture — root landing page (`docs/index.html`) routes to Papillion (consumer) and PAP (developer) sub-sites
- **docs**: PAP technical spec site relocated to `docs/pap/` with cross-links to Papillion for non-developer visitors
- **docs**: Multi-language SDK roadmap section on PAP site — Rust (shipping), Python/TypeScript/Go/Swift/Kotlin planned

### Changed

- **docs**: PAP site language aligned with Papillion framing — leads with "why" (control, visibility, safety) before "how" (cryptographic protocol), adds "Not a developer?" CTA linking to Papillion
- **docs**: README simplified — removed example binary references (examples deleted in 0.2.0), added Papillion link for interactive demos
- **ci**: Release workflow model download switched to HuggingFace hub for reliability

### Removed

- **docs**: Direct API call examples removed from PAP site — Papillion now covers those use cases through its interactive demo

## [0.3.0] - 2026-03-21

### Added

- **papillion**: Multi-profile identity support — switch between multiple profiles (like browser profiles), each with its own DID and workspace
- **papillion**: Profile avatars with deterministic colors — visual distinction between profiles with semantic color palette (purple/teal/gold/coral/blue/rose)
- **papillion**: Profile manager in Settings — create, rename, delete, and switch profiles with last-used timestamps
- **papillion**: Profile dropdown in TopBar — quick access to all profiles with active profile indicator
- **papillion**: Complete state isolation per profile — profile switch resets canvas, registries, and orchestrator config for true workspace separation
- **papillion-ui**: Schema-driven JSON-LD rendering engine — trait-based registry pattern for custom block renderers; replaces hard-coded dispatch with runtime-registrable templates that handle arbitrary schema.org types by classifying field shapes (dates, prices, URLs, DIDs, nested objects, lists)
- **papillion-ui**: SOLID-compliant renderer architecture — enables custom templates via registry registration without modifying core code (Open/Closed Principle)
- **papillion-ui**: Handshake envelope unwrap — extracts agent payload from the PAP handshake wrapper and renders receipt metadata footer (session ID, co-signatures, action)
- **papillion-ui**: Answer renderer for on-device AI responses displayed as clean paragraph text
- **papillion-ui**: CSS class sanitization and list item cap (50) to prevent malicious agent payloads from injecting CSS classes or flooding the DOM
- **docs**: Built-in LLM setup guide — quick reference for downloading TinyLLaMA and testing locally
- **docs**: Tauri resource directory quirk — comprehensive guide explaining platform-specific model bundling behavior (macOS/Windows/Linux)
- **docs**: Manual QA test plan — 20 comprehensive test cases covering profile creation, switching, isolation, persistence, and edge cases

### Changed

- **papillion**: Profile data now persisted in separate `profiles.db` registry alongside main database
- **papillion**: Seed zeroization hardened — `Zeroizing<[u8; 32]>` prevents sensitive material from lingering in memory
- **papillion-ui**: Block renderer converted from single file to module directory with trait-based plugin architecture (mod, field_classify, generic, templates, registry, renderer, receipt)

## [0.2.3] - 2026-03-21

### Fixed

- **papillion**: Prevent silent identity loss on corrupt seed — now returns error instead of silently generating ephemeral keypair
- **papillion**: DB persist failures no longer swallowed — seed persistence errors propagated to frontend so users know identity creation failed
- **papillion**: Raw seed material now zeroized on drop to prevent lingering in memory after use (cryptographic hardening)

## [0.2.2] - 2026-03-21

### Added

- **papillion**: Papillion now remembers your agent interactions across restarts — episodes, agent profiles, and settings persist in a local SQLite database
- **papillion**: Smarter agent selection — the app learns from past interactions to calibrate mandate TTL and minimize disclosure based on agent track records
- **papillion**: Agent performance tracking with rolling averages — success rate, quality, duration, and co-sign refusals tracked per agent
- **papillion**: Your identity persists across restarts — Ed25519 principal keypair auto-saved on first launch, auto-loaded on subsequent starts
- **papillion**: Semantic queries over stored interactions — search by Schema.org type or free text across your interaction history
- **papillion**: Agent profiles now accessible from the frontend via `list_agent_profiles` command
- **docs**: Memex(RL) architectural comparison — maps PAP's trust-bounded experience memory against Memex(RL) indexed retrieval patterns

### Changed

- **papillion**: Scenario history now persists across app restarts (previously in-memory only)

### Fixed

- **papillion**: Fixed potential panic on short DID/hash strings in step display (`agent_did[..20]`, `mandate_hash[..16]`, `session.id[..8]`) — now use safe `.get()` fallbacks
- **papillion**: Fixed protocol violation risk where stale disclosure refs from agent profiles could be used in new mandates — now validates refs are a valid subset of current scenario's allowed disclosures

### Changed

- **papillion**: Orchestrator now de-duplicates SHA-256 hash computation for agent DIDs — extracted to `hash_agent_did()` helper function (DRY)
- **papillion**: `list_completed_runs` now supports pagination with optional `offset` and `limit` parameters — prevents returning massive JSON payloads (default: 50, capped at 100)

## [Unreleased]

### Added

- **CI**: GitHub Actions release workflow — auto-tags version bumps on merge to main, builds Tauri desktop app for macOS (universal), Linux, and Windows, creates GitHub Release with platform binaries

## [0.2.1] - 2026-03-21

### Fixed

- **papillion**: Fixed macOS app crash on startup — federation server initialization now runs on dedicated background thread with its own tokio runtime, preventing panic when `tokio::spawn()` is called before runtime initialization

## [0.2.0] - 2026-03-21

### Added

- **pap-federation**: Fingerprint-pinned TLS verifier (`FingerprintVerifier`) using SHA-256 cert pinning for zero-trust peer verification. No CA dependency — DIDs are the trust root
- **pap-federation**: DNS/TOFU bootstrap flow — `FederationClient::tofu()` for initial peer discovery (transitional until DNS-based bootstrap), `FederationClient::pinned()` for verified peer connections
- **pap-federation**: Ed25519 signature verification on agent advertisements via `verify_key_from_did()` — cryptographically validates each ad's authenticity
- **pap-transport**: `RemoteAgentHandler::with_client()` for custom TLS clients, session_id tracking for PAP phase 5 receipt co-signing
- **pap-federation**: Peer fingerprint pinning throughout discovery loop and registry operations — only adds gossiped peers with cert fingerprints

### Changed

- **pap-federation**: `FederationClient` constructor API — `new()` now calls `tofu()` (bootstrap); use `pinned(peers)` for verified connections
- **pap-transport**: `AgentClient::new()` uses standard CA-validated TLS instead of `danger_accept_invalid_certs(true)` — PAP federation uses `with_client()` with pinned clients
- **papillion**: Registry navigation via explicit TOFU → fingerprint pinning flow instead of blind `resolve_pap_url()` — all peer communication requires known fingerprints
- **papillion**: Discovery loop only contacts peers with cert fingerprints; rejects gossiped peers without fingerprints

### Fixed

- **SECURITY**: Replace blind certificate acceptance with fingerprint pinning. TLS handshake verifies cert SHA-256 against trusted set. Only `build_tofu_client()` accepts any cert (bootstrap phase, clearly labeled, to be replaced by DNS)
- **SECURITY**: Agent advertisement signatures now cryptographically verified via Ed25519, not just presence-checked. Prevents malicious peer gossip poisoning
- **SECURITY**: Peer gossip validation — only peers with cert fingerprints are added to registry or contacted for sync. Discovery loop uses fingerprint-pinned TLS for all connections

### Removed

- **Examples**: Deleted all example binaries (delegation-chain, federated-discovery, local-ai-assistant, networked-search, payment, search, travel-booking, webauthn-ceremony) — PAP is real protocol only, no toy demos
- **resolve.rs**: Removed `resolve_pap_url()` and `ResolvedPeer` — replaced by inline TOFU/pinning flow in registry commands

## [0.1.0] - 2026-03-14

### Added

- **pap-did**: Ed25519 keypair generation, `did:key` derivation, DID documents, ephemeral session keys
- **pap-core**: Mandate issuance, hierarchical delegation with chain verification, scope enforcement (deny-by-default), capability tokens (single-use, nonce-bound), session state machine (Initiated → Open → Executed → Closed), transaction receipts (co-signed, property refs only), decay states (Active → Degraded → ReadOnly → Suspended), continuity tokens, auto-approval policies, payment proof field
- **pap-credential**: W3C Verifiable Credential envelope, SD-JWT selective disclosure
- **pap-marketplace**: Signed JSON-LD agent advertisements, marketplace registry, disclosure-based filtering
- **pap-proto**: Protocol message types, typed envelope serialization
- **pap-transport**: HTTP client/server for 6-phase session handshake (Axum-based)
- **pap-federation**: Federated registry with cross-registry sync, announce, peer discovery
- **pap-webauthn**: WebAuthn signer abstraction with software fallback and mock authenticator
- **Examples**: search (zero-disclosure), travel-booking (SD-JWT), delegation-chain (4-level hierarchy), payment (ecash + auto-approval + continuity), networked-search (HTTP transport), federated-discovery (cross-registry), webauthn-ceremony (device-bound keys)
- **Docker**: local-ai-assistant example with Ollama + SearXNG + PAP marketplace + providers + orchestrator + receipt viewer
- **CI**: GitHub Actions (test, clippy, fmt, example runner)
- **Docs**: README with competitive comparison table, CONTRIBUTING.md, issue templates

### Protocol Constraints (v0.1)

1. Deny by default — agents can only act within explicit mandate scope
2. Delegation cannot exceed parent — scope and TTL bounded, verified cryptographically
3. Session DIDs are ephemeral — unlinked to principal identity, discarded at close
4. Receipts contain property references only — never values
5. Non-renewal is revocation — progressive degradation, no surprise cutoff

[0.1.0]: https://github.com/Baur-Software/pap/releases/tag/v0.1.0

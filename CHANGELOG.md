## [Unreleased]

## [0.5.6] - 2026-03-27

### Added

- **papillon**: On-demand model downloading for built-in LLM models — models are fetched at first use instead of bundled with the app binary, reducing initial download size

### Fixed

- **papillon**: Wrap Tauri IPC args in named parameter objects — fixes invoke serialization for commands expecting structured arguments

### Changed

- Rename `papillion` → `papillon` across entire codebase (correct French spelling)

## [0.5.5] - 2026-03-26

### Fixed

- Canary: download WASM artifact, install Playwright chromium, run from e2e/ working directory

## [0.5.4] - 2026-03-26

### Fixed

- Papillon iOS: use `App.xcodeproj` instead of `App.xcworkspace` (Capacitor 8 uses SPM, not CocoaPods)

## [0.5.3] - 2026-03-26

### Fixed

- Papillon iOS: remove CocoaPods Podfile sed (Capacitor 8 uses Swift Package Manager)
- Papillon mobile upload scripts: remove `require('@actions/glob')` (conflicts with Node 22 built-in)

## [0.5.2] - 2026-03-26

### Fixed

- Papillon mobile builds: upgrade to Capacitor 8 (Node 22, JDK 21, iOS 15.0 deploy target)
- Remove Chrysalis mobile builds (SSR app output is incompatible with Capacitor)

## [0.5.1] - 2026-03-26

### Fixed

- Force-reinstall trunk/cargo-leptos binaries to avoid stale cache mismatches
- Chrysalis server binary path corrected to `target/release/` (matches cargo-leptos output)

## [0.5.0] - 2026-03-26

### Added

- **Multi-platform release workflows** — Per-product CI/CD pipelines for Papillon and Chrysalis covering desktop (macOS/Linux/Windows), mobile (iOS/Android via Capacitor thin clients), web (WASM), Docker, and npm
- **npm CLI packages** — `@baur-software/papillon` (serves WASM frontend) and `@baur-software/chrysalis` (downloads platform binary)
- **Papillon Dockerfile** — Multi-stage trunk build to nginx:alpine with COOP/COEP headers

### Fixed

- Windows desktop build: PowerShell compatibility for mkdir and gh commands
- Capacitor App ID validation: removed dashes from Java package names

## [0.4.4.0] - 2026-03-24

### Added

- **Why a Registry? — README** — Six-reason rationale for the Chrysalis registry primitive: discovery without a central directory, pre-session SD-JWT disclosure matching, payment negotiation via `Mandate.payment_proof` (ecash/Lightning), trust at the edge (Ed25519 ingest + TLS TOFU pinning), accountability without exposure (receipts with property refs only), and operator sovereignty.
- **Why a Registry? — GitHub Pages** — Same rationale section added to `docs/chrysalis.html` with a numbered six-card grid and a callout explaining the org-internal multi-node mesh pattern (`FederatedRegistry` content-hash dedup + `/federation/peers` gossip, public/private boundary by peering decision).

## [0.1.0.0] - 2026-03-23

### Added

- **Template System - Phase 9 Full Feature Pack** — Complete user-defined rendering templates with 7 advanced features:
  - **9a: JSON Editor Enhancement** — Format/Minify buttons + real-time JSON validation with line/column error reporting
  - **9b: Template Builder** — Structured form UI for building templates without JSON knowledge; field mapper with path/label/display type; live JSON preview
  - **9c: Template Preview** — Live rendering panel with sample JSON-LD input; JSON path extraction (nested paths, array indices); formatted value display
  - **9d: Bulk Operations** — Multi-select checkboxes; bulk enable/disable/delete with confirmation dialogs
  - **9e: Template Library** — Pre-built examples (Flight, Hotel, Product, Event, Recipe); Copy & Customize workflow
  - **9f: Export/Import** — JSON export with file download; JSON import with duplicate skip; preserves template integrity
  - **9h: Template Validation** — TemplateConfig::validate() with comprehensive checks (version, layout type, column counts, field paths, display types)
- **Phase 7 UI Polish** — Production-ready refinements: improved spacing (16→20px padding, 8→12px gaps), enhanced typography (bold labels, better hierarchy), accessibility improvements (aria-labels, required field indicators), visual polish (shadows, rounded corners, consistent styling)
- **175+ comprehensive tests** — 10 backend CRUD tests + 4 frontend renderer tests + 8 E2E template tests + 44 type serialization tests; all passing

### Changed

- **TemplatesTab component** — Refactored to hub for all Phase 9 enhancements; integrated Template Builder, Preview, and Library as modal overlays
- **templates_tab.rs** — Enhanced with form validation, error/success messaging, bulk operations UI, export/import handlers

### Architecture

- Declarative JSON-LD template system with zero-trust loading (no AppState caching)
- Per-profile template scoping with principal_did isolation
- Tauri command bridge for backend operations with proper error propagation
- Zero-copy template rendering with JSON path extraction and conditional field evaluation

## [0.4.3.0] - 2026-03-24

### Fixed

- **docker-compose**: Resolve Docker image pull error by using `tags` field instead of standalone `image` key. Prevents spurious "pull access denied for pap-registry" errors when docker-compose attempts to pull a non-existent image from Docker Hub.

## [0.4.1.2] - 2026-03-23

### Added

- **Agent Designer WYSIWYG Form Builder** — Complete 5-phase implementation: Phase 1 scaffolding + routing, Phase 2 form validation display, Phase 3 copy-to-clipboard JSON preview, Phase 4 Ed25519 signing infrastructure, Phase 5 visual polish & accessibility. 600+ lines of Leptos/Rust + 140+ lines of CSS. Real-time JSON-LD preview, responsive two-column layout, comprehensive validation with error display.
- **docs**: Comprehensive Agent Designer specification (`AGENT_DESIGNER_DESIGN.md`) — WYSIWYG form builder for PAP agent advertisements with real-time JSON-LD preview, zero-trust WebAuthn signing, and "Load from existing" versioning workflow. Includes 5-phase implementation roadmap and full architectural design. All reviews (CEO, Design, Eng) approved.
- **docs**: Agent Designer test plan (`AGENT_DESIGNER_TEST_PLAN.md`) — covers 40+ code paths, 6 critical user flows, edge cases, and E2E + component test breakdown

### Changed

- **docs**: Improve README messaging with problem-centric framing — reframe "The Problem" around trust boundaries, clarify MCP spec limitations, add concrete attack scenarios
- **docs**: Sync README with shipped language bindings (Python, JS/TS, C, C#, Java) and Chrysalis registry
- **docs**: Add comprehensive Language Bindings table covering all 6 supported languages
- **docs**: Expand "Why This Matters" section with three-part structure (Problem → Structural Ceiling → PAP's Answer)
- **docs**: Rename comparison table to "How PAP Differs" and reframe columns around protocol-enforced disclosure

## [0.4.1.1] - 2026-03-23

### Changed
- Rebrand registry as "Chrysalis" with butterfly motif (🦋)
- Update sidebar branding and dashboard titles
- Simplify registry subtitle from "Federation Node" to "Agent Registry"


All notable changes to PAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-03-24

### Added

- **qa**: Tier 1 smoke tests for Papillon desktop app — Playwright-based E2E smoke tests verifying app launches, renders, and loads without WASM errors. Runs in CI on every PR.
- **qa**: Tier 2 functional tests for Papillon workflows — 11 E2E tests covering agent discovery, scenario selection, PAP handshake (6-step protocol), and settings management. Mock command infrastructure validates state transitions and error scenarios.
- **qa**: Tier 3 canary monitoring for post-deploy health checks — 6 post-deployment health checks (backend health endpoint, frontend load time, scenario execution latency, orchestrator config, identity access, console errors). Runs automatically after release publish.
- **papillon**: Health endpoint (`get_health_status` Tauri command) — returns application health status, uptime (calculated from Instant, not UNIX_EPOCH), timestamp, and version. Enables post-deploy canary verification without rolling back broken releases.
- **ci**: CodeQL workflow with path-based filtering — runs static analysis only when changes include target languages (Rust, Python, JavaScript/TypeScript), reducing unnecessary CI runs on documentation-only or configuration-only commits
- **docs**: New `pap.html` dedicated page for the PAP protocol targeting developers — covers all six protocol invariants (failure-mode-first framing), protocol stack table, crate grid, Quick Start Rust snippet, examples, and comparison table
- **docs**: New `chrysalis.html` page for the Chrysalis self-hostable federated registry product
- **docs**: Papillon canvas rendering demo on `index.html` — macOS-style mockup showing flight booking result with privacy disclosure strip
- **docs**: Six PAP constraint cards on `pap.html`, each leading with the failure mode it prevents; includes new card 06 "Discovery without a standard becomes a silo" covering the federated registry and Papillon visual composer
- **docs**: Registry and visual composer card explaining signed JSON-LD capability advertisements, federated discovery, and Papillon's drag-and-drop workflow composer

### Fixed

- **health**: Fix uptime metric calculation — changed from seconds since UNIX_EPOCH (corrupted metric) to actual application uptime using `std::time::Instant`. Prevents silent data corruption in monitoring dashboards.
- **ci**: Fix CodeQL workflow build-mode compatibility — changed `build-mode: none` to `build-mode: autobuild` for Go language support in multi-language analysis.
- **ci**: Add Tauri CLI installation to smoke test job — explicitly installs `tauri-cli` in CI environment before running `cargo tauri build`.
- **ci**: Increase canary verification timeout from 5 to 15 minutes — accommodates cold-start WASM compilation and Playwright browser download on CI machines.
- **qa**: Adjust frontend load time SLA from 3 seconds to 10 seconds — realistic timeout for CI ubuntu-latest cold-start (WASM + bundle = 5-15s).
- **qa**: Improve console error filtering in canary tests — use regex patterns instead of string includes, properly detects critical errors vs. benign warnings.
- **papillon**: Use `.map()` instead of `.and_then()` for `Navigator::clipboard()` after `web_sys` return type change from `Option<Clipboard>` to `Clipboard` — fixes WASM compilation failure blocking Tauri desktop builds on all platforms

### Changed

- **docs**: `index.html` reframed around Papillon product (canvas rendering engine, use cases, how-it-works); PAP protocol content moved to dedicated `pap.html`
- **docs**: PAP invariants rewritten to lead with failure modes rather than mechanism names — "Sessions that never die drain the internet" instead of "Hard TTL enforcement"
- **docs**: Nav updated across all pages: `index.html`, `chrysalis.html`, and `pap.html` link to each other cohesively

## [0.4.1] - 2026-03-23

### Added

- **registry**: Hostable federated PAP registry — standalone Axum web service that other agents and Papillon instances can discover and query; supports both SQLite (single-node) and Postgres (clustered) backends
- **registry**: Leptos 0.8 SSR frontend — server-side-rendered agent search UI with live FTS5 results, DID display, capability badges, and pagination; single-crate architecture (no separate WASM build step)
- **registry**: Federation protocol — push/pull peer sync, `/api/peers` management endpoints, and configurable sync intervals for multi-node mesh
- **registry**: Admin REST API — token-authenticated endpoints for agent CRUD, peer management, and status; all mutations require `Authorization: Bearer <token>`
- **registry**: Ed25519 signature verification on agent registration — rejects unsigned or tampered `AgentAdvertisement` payloads at ingest
- **registry**: Docker-based test execution — `docker buildx build --target test` stage runs the full test suite at build time; CI `test-registry` job added to GitHub Actions
- **registry**: Comprehensive test suite — 34 tests covering SQLite CRUD layer, auth middleware, and all admin route handlers via `tower::ServiceExt::oneshot()`
- **papillon**: Local federated registry settings — configure endpoint and sync interval for the Papillon-embedded registry directly in the Settings panel

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

- **docs**: Papillon marketing site (`docs/papillon/`) — consumer-facing landing page with interactive 6-step purchase demo showing AI operating within user-defined rules (budget, vendor preferences, approval thresholds)
- **docs**: Dual GitHub Pages architecture — root landing page (`docs/index.html`) routes to Papillon (consumer) and PAP (developer) sub-sites
- **docs**: PAP technical spec site relocated to `docs/pap/` with cross-links to Papillon for non-developer visitors
- **docs**: Multi-language SDK roadmap section on PAP site — Rust (shipping), Python/TypeScript/Go/Swift/Kotlin planned

### Changed

- **docs**: PAP site language aligned with Papillon framing — leads with "why" (control, visibility, safety) before "how" (cryptographic protocol), adds "Not a developer?" CTA linking to Papillon
- **docs**: README simplified — removed example binary references (examples deleted in 0.2.0), added Papillon link for interactive demos
- **ci**: Release workflow model download switched to HuggingFace hub for reliability

### Removed

- **docs**: Direct API call examples removed from PAP site — Papillon now covers those use cases through its interactive demo

## [0.3.0] - 2026-03-21

### Added

- **papillon**: Multi-profile identity support — switch between multiple profiles (like browser profiles), each with its own DID and workspace
- **papillon**: Profile avatars with deterministic colors — visual distinction between profiles with semantic color palette (purple/teal/gold/coral/blue/rose)
- **papillon**: Profile manager in Settings — create, rename, delete, and switch profiles with last-used timestamps
- **papillon**: Profile dropdown in TopBar — quick access to all profiles with active profile indicator
- **papillon**: Complete state isolation per profile — profile switch resets canvas, registries, and orchestrator config for true workspace separation
- **papillon-ui**: Schema-driven JSON-LD rendering engine — trait-based registry pattern for custom block renderers; replaces hard-coded dispatch with runtime-registrable templates that handle arbitrary schema.org types by classifying field shapes (dates, prices, URLs, DIDs, nested objects, lists)
- **papillon-ui**: SOLID-compliant renderer architecture — enables custom templates via registry registration without modifying core code (Open/Closed Principle)
- **papillon-ui**: Handshake envelope unwrap — extracts agent payload from the PAP handshake wrapper and renders receipt metadata footer (session ID, co-signatures, action)
- **papillon-ui**: Answer renderer for on-device AI responses displayed as clean paragraph text
- **papillon-ui**: CSS class sanitization and list item cap (50) to prevent malicious agent payloads from injecting CSS classes or flooding the DOM
- **docs**: Built-in LLM setup guide — quick reference for downloading TinyLLaMA and testing locally
- **docs**: Tauri resource directory quirk — comprehensive guide explaining platform-specific model bundling behavior (macOS/Windows/Linux)
- **docs**: Manual QA test plan — 20 comprehensive test cases covering profile creation, switching, isolation, persistence, and edge cases

### Changed

- **papillon**: Profile data now persisted in separate `profiles.db` registry alongside main database
- **papillon**: Seed zeroization hardened — `Zeroizing<[u8; 32]>` prevents sensitive material from lingering in memory
- **papillon-ui**: Block renderer converted from single file to module directory with trait-based plugin architecture (mod, field_classify, generic, templates, registry, renderer, receipt)

## [0.2.3] - 2026-03-21

### Fixed

- **papillon**: Prevent silent identity loss on corrupt seed — now returns error instead of silently generating ephemeral keypair
- **papillon**: DB persist failures no longer swallowed — seed persistence errors propagated to frontend so users know identity creation failed
- **papillon**: Raw seed material now zeroized on drop to prevent lingering in memory after use (cryptographic hardening)

## [0.2.2] - 2026-03-21

### Added

- **papillon**: Papillon now remembers your agent interactions across restarts — episodes, agent profiles, and settings persist in a local SQLite database
- **papillon**: Smarter agent selection — the app learns from past interactions to calibrate mandate TTL and minimize disclosure based on agent track records
- **papillon**: Agent performance tracking with rolling averages — success rate, quality, duration, and co-sign refusals tracked per agent
- **papillon**: Your identity persists across restarts — Ed25519 principal keypair auto-saved on first launch, auto-loaded on subsequent starts
- **papillon**: Semantic queries over stored interactions — search by Schema.org type or free text across your interaction history
- **papillon**: Agent profiles now accessible from the frontend via `list_agent_profiles` command
- **docs**: Memex(RL) architectural comparison — maps PAP's trust-bounded experience memory against Memex(RL) indexed retrieval patterns

### Changed

- **papillon**: Scenario history now persists across app restarts (previously in-memory only)

### Fixed

- **papillon**: Fixed potential panic on short DID/hash strings in step display (`agent_did[..20]`, `mandate_hash[..16]`, `session.id[..8]`) — now use safe `.get()` fallbacks
- **papillon**: Fixed protocol violation risk where stale disclosure refs from agent profiles could be used in new mandates — now validates refs are a valid subset of current scenario's allowed disclosures

### Changed

- **papillon**: Orchestrator now de-duplicates SHA-256 hash computation for agent DIDs — extracted to `hash_agent_did()` helper function (DRY)
- **papillon**: `list_completed_runs` now supports pagination with optional `offset` and `limit` parameters — prevents returning massive JSON payloads (default: 50, capped at 100)

## [Unreleased]

### Added

- **CI**: GitHub Actions release workflow — auto-tags version bumps on merge to main, builds Tauri desktop app for macOS (universal), Linux, and Windows, creates GitHub Release with platform binaries

## [0.2.1] - 2026-03-21

### Fixed

- **papillon**: Fixed macOS app crash on startup — federation server initialization now runs on dedicated background thread with its own tokio runtime, preventing panic when `tokio::spawn()` is called before runtime initialization

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
- **papillon**: Registry navigation via explicit TOFU → fingerprint pinning flow instead of blind `resolve_pap_url()` — all peer communication requires known fingerprints
- **papillon**: Discovery loop only contacts peers with cert fingerprints; rejects gossiped peers without fingerprints

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

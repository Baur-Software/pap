## [Unreleased]

## [0.7.2] - 2026-04-04

### Changed

- **papillon-extension**: Hardened Content Security Policy from 2 directives to 9 — added `default-src 'none'` deny-by-default baseline, explicit `style-src`, `font-src`, `img-src`, `connect-src`, `base-uri`, and `form-action` directives. Extension pages can no longer load unauthorized resource types.
- **papillon-extension**: Replaced `Function()` constructor (eval-equivalent) in WASM loader with CSP-compliant `import(/* @vite-ignore */)` dynamic import. No `unsafe-eval` needed.
- **papillon-extension**: Firefox manifest CSP now derived from Chrome manifest instead of hardcoded duplicate, keeping both in sync automatically.

### Fixed

- **papillon-extension**: Replaced `innerHTML = ""` with `replaceChildren()` at three call sites in handshake UI, aligning with the codebase's "never innerHTML" security policy.

### Added

- **ci**: Java JNA binding integration tests now run in CI — builds `libpap_c.so` and executes 85+ JUnit tests covering keypairs, mandates, scopes, decay states, sessions, and capability tokens via Gradle on every push and PR
- **pap-python**: 48 new negative-path and security-invariant tests for Session, CapabilityToken, and TransactionReceipt — covers invalid state transitions, tamper detection, expiry enforcement, insufficient signatures, ephemeral DID unlinkability, Mandate decay state progression, and delegation scope/TTL constraints
- **pap-python**: Shared conftest.py with pytest fixtures for keypairs, tokens, sessions, and mandates

### Fixed

- **pap-python**: Corrected receiver_did/target_did mismatches in existing test suite (enforced by Rust core's CapabilityToken.verify)
- **pap-python**: Fixed test_delegate race condition and test_decay_state window calculation in test_basic.py

## [0.7.2.1] - 2026-04-05

### Changed

- **docs**: Expanded CONTRIBUTING.md with comprehensive development environment setup guide — prerequisites (Rust, system libs, optional tooling), quick start commands, project structure tour, per-subsystem test instructions (Rust, Python, Java, E2E), example runner commands, browser extension build steps, CI pipeline table with local reproduction commands, branch naming and conventional commit conventions
- **ci**: Hardened benchmark regression gate — tightened threshold from 20% to 10%, added artifact-based baseline storage with 90-day retention so PRs compare against the latest main baseline instead of a stale committed file, added benchmark summary PR comments via `actions/github-script`, and improved `check_regression.sh` with `--baseline`/`--output` flags and proper argument parsing
- **ci**: Added zero-value guard in `check_regression.sh` — a Criterion parse failure that yields 0 now fails the gate instead of silently passing
- **ci**: Baseline update on main push now runs even if the regression check fails, preventing a single noisy benchmark from permanently jamming the CI gate

## [0.7.1] - 2026-04-04

### Added

- **pap-c**: C FFI marketplace query API — `PapMarketplaceClient` opaque handle wrapping `MarketplaceRegistry`, `PapAgentList` typed result set with index-based accessors (`pap_agent_list_get_did`, `pap_agent_list_get_name`), JSON-based `pap_marketplace_query` dispatching to `query_by_action` or `query_satisfiable` based on `available_properties` presence, and `pap_last_error` alias for error retrieval
- **pap-c**: 11 unit tests covering client lifecycle, query dispatch, disclosure filtering, out-of-bounds safety, null-pointer guards, invalid JSON rejection, and unsigned advertisement rejection

### Changed

- **github**: Replaced generic markdown issue templates with structured YAML Issue Forms for all four pillars (Papillon, Chrysalis, papillon-extension, pap:// URI). Each form now enforces required fields — blank issues are denied via `config.yml`. Forms cover pillar-specific fields: OS/area selector for Papillon, deployment type and federation peer count for Chrysalis, browser version and native host for the extension, and protocol phase (1–6) for pap:// URIs. Replaced the single protocol feedback template with a structured `protocol-proposal.yml` that requires a capture-test evaluation for every proposal. Added a cross-cutting `feature-request.yml` with capture-test and non-goals guardrails.

## [0.7.0] - 2026-04-04

### Added

- **papillon-extension**: PAP site discovery — Layer 0+1 detection with DOM signal check and same-origin manifest probe; icon badge indicates when current site supports PAP
- **papillon-extension**: Context menu upgrade — right-click HTTPS links to open via PAP-secured handshake; falls back to unprotected URL on failure with copyable link
- **papillon-extension**: Popup site indicator — displays agent name and "PAP Agent Available" status for current page
- **papillon-extension**: Persistent badge state via `chrome.storage.session` — survives service worker restart

### Fixed

- **papillon-extension**: Same-origin enforcement on `<link rel="pap-manifest">` — cross-origin manifest URIs are now rejected
- **papillon-extension**: Manifest validation now bounds all strings and arrays — `agent_id`/`name` ≤1000 chars, `tools` ≤500 items, `categories` ≤100 items, `description`/`endpoint` ≤1000/500 chars
- **papillon-extension**: Response body size bounded to 100KB to prevent DoS via oversized manifests
- **papillon-extension**: Added Content-Type validation on manifest response (must be `application/json`)
- **papillon-extension**: URL parsing heuristic fixed — now uses proper URL parsing instead of substring sniffing
- **papillon-extension**: Timer resource leak fixed in manifest fetch error path (now uses try/finally)
- **papillon-extension**: Firefox compatibility — removed optional chaining on `chrome.contextMenus` and `chrome.storage` APIs
- **papillon-extension**: Fallback URL validation — only `http://` and `https://` schemes allowed (blocks javascript: injection)

## [0.6.0] - 2026-04-02

### Added

- **pap-agents**: `DynamicAgentDef` data model — runtime agent definition with HTTP endpoint config, LLM instructions, subagent references, and operator key seed for self-sovereign DID derivation
- **pap-agents**: `DynamicAgentHandler` — hybrid execution engine that routes requests to HTTP endpoints or LLM inference based on agent config, with schema.org JSON-LD normalization
- **pap-agents**: `AgentSet::register_dynamic()` — runtime registration of dynamic agents with cryptographic signing and advertisement publication (spec §9.1)
- **pap-agents**: Catalog loader — recursive TOML reader for `catalog/` directory with SSRF URL validation via `is_safe_url`
- **pap-agents**: 22 TOML catalog entries across 8 domains (culture, finance, food, geo, government, health, knowledge, science, search, sports)
- **papillon-shared**: `agents` table migration with CRUD operations for persistent user-created agent storage
- **papillon**: Catalog seeding at startup — loads all TOML agents into the local registry on first launch
- **papillon**: 7 agent lifecycle Tauri commands: `list_local_agents`, `save_agent`, `delete_agent`, `update_agent`, `generate_agent`, `publish_agent`, `unpublish_agent`
- **papillon**: Extended `AgentInfo` struct with `source`, `catalog_path`, `operator_key_seed`, `agent_did`, `published_to` fields
- **papillon-ui**: Terminal aesthetic shell — dot-grid background, 64px icon sidebar with SVG nav icons, `PAPILLON_SYS` topbar with DID display and session badge, bottom status bar
- **papillon-ui**: System readiness dashboard — live diagnostics for identity, LLM, and federation status
- **papillon-ui**: Agent fleet page — live agent roster with source badges (catalog/user/federation), action chips, and disclosure requirements
- **papillon-ui**: Negotiation ledger — PAP handshake event log with trust levels, session IDs, and session stats
- **papillon-ui**: Receipts page — co-signed transaction receipt browser with PRINCIPAL/AGENT signature verification cards
- **papillon-ui**: Setup wizard restyle as terminal init sequence with boot header, 3-step progress strip, and provider selection cards
- **papillon-ui**: Intent partitions timeline — episode browser with ALL/ACTIVE/DEGRADED/COMPRESSED filter, scope tags, and partition outcome indicators
- **papillon-ui**: 3-panel canvas workspace — collapsible intent panel (left), main viewport (center), ledger panel (right)
- **papillon-ui**: Mandate builder tab in system settings — visual JSON-LD preview with reactive form fields
- **papillon-ui**: Human-in-the-loop gate modal — `HitlRequest` struct drives authorization overlay for critical agent actions
- **pap-registry**: Per-principal advertisement rate limit (max 100 ads/principal) enforced in Chrysalis federation server
- **papillon-shared**: `resolve_pap_uri` — three-tier resolution chain for `pap://`, `pap+https://`, and `pap+wss://` URIs (DID passthrough, catalog name rewrite, registry hostname passthrough, special authority dispatch)
- **papillon-shared**: `LinkOrigin` enum — `Principal` vs `Agent` origin enforced at resolver level; agent-rendered links cannot activate `receipt`, `canvas`, or `settings` special authorities
- **papillon-ui**: `CatalogState` — reactive `name → DID` index rebuilt from registry agent list; keeps first entry on name collision to prevent silent intent redirection
- **papillon-ui**: `FieldKind::PapLink` — pap:// links in block renderer render as confirmation-gated `<button>` with scheme/body visual split; `ExternalUrl` replaces prior `Url` variant for plain HTTP/HTTPS
- **papillon-ui**: `pap+https://` and `pap+wss://` parse and classify in v1.0 but activation returns a clear "recapture enforcement not yet available" error — never silently downgraded to plain HTTPS

### Changed

- **pap-agents**: Deleted 13 compiled agent implementations in favor of TOML catalog entries (DuckDuckGo, Hacker News, Wikipedia, and 10 others now defined declaratively)
- **papillon**: Topbar brand icon updated from shield SVG to `logo.png`
- **papillon**: Home page hero updated from shield SVG to `logo.png`

### Fixed

- **pap-agents**: Add missing `PathBuf` import in `catalog.rs` test module
- **papillon**: Handshake integration test updated from deleted Hacker News compiled agent to echo executor, testing protocol mechanics without network dependency

## [0.5.9] - 2026-04-01

### Fixed

- **pap-python**: Add `build.rs` to emit `-undefined dynamic_lookup` linker flag on macOS, fixing linker errors when building the PyO3 extension module (`cdylib`) — Python symbols are resolved at load time by the embedding interpreter, not at build time

## [0.5.8] - 2026-03-29

### Fixed

- **papillon**: Fix disposed NodeRef panic when navigating away from canvas — eagerly capture DOM element in reactive context instead of accessing NodeRef inside setTimeout callback
- **papillon**: serde_wasm_bindgen double-serialization handling — `Option::None` becomes JS `undefined` (not `null`), requiring loose equality (`== null`) and nullish coalescing (`??`) in E2E mocks
- **papillon**: Remove dead code duplicate `search_agents` case that shadowed the full implementation with query/actionType filtering
- **papillon**: Null normalization for `principal_did` and `created_by` in template create/update paths

### Changed

- **papillon**: Canvas shows LLM provider setup prompt when orchestrator is disconnected, with link to Settings
- **papillon**: Canvas prompt label "What do you want to build?" added above input
- **papillon**: Topbar status label changed from "Papillon" to "Ready" when orchestrator is connected
- **papillon**: Template placeholders improved ("Name (e.g., My Flight Template)", "Schema type (e.g., FlightReservation)")
- **papillon**: Template list uses composite key (id + schema_type + enabled + updated_at) for immediate UI updates on edit/toggle
- **e2e**: Complete template CRUD test rewrite — 8 tests covering create, read, edit, delete, enable/disable, persistence, validation, and default templates
- **e2e**: Tauri mock updated with `mapToObj()` for serde_wasm_bindgen Map→Object conversion, updated agent format (provider_name, capabilities, object_types), and snake_case arg fallbacks
- **e2e**: App shell tests updated for 5-tab settings layout and new canvas empty state navigation

## [0.4.5.0] - 2026-03-29

### Added

- **papillon**: Auto-generate declarative templates from JSON-LD agent results when no matching template exists for a schema type
- **papillon-shared**: `generate_template_from_json_ld` function with field classification (date, price, url, title, text) based on key names and value shapes
- **papillon-shared**: `has_enabled_template_for_schema_type` trait method for native, WASM, and IndexedDB database backends
- **papillon**: `auto_generate_template` Tauri command for explicit frontend-triggered template generation
- **papillon**: Automatic template generation in canvas prompt and reshape flows (fire-and-forget, never blocks results)

## [0.5.7] - 2026-03-27

### Fixed

- Sync `tauri.conf.json` version with workspace — desktop artifacts (rpm, deb, dmg, exe, msi, AppImage) now use the correct version in filenames

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

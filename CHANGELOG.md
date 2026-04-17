## [Unreleased]

### Added

- **pap-transport**: Real RFC 9458 Oblivious HTTP with HPKE
  (DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM). Relay operators and passive
  observers can no longer read SD-JWT disclosure structure. Stateful per-request
  `OhttpResponseDecryptCtx` / `OhttpResponseEncryptCtx` bind each response
  cryptographically to its corresponding request via HPKE context export. Server keypair
  management via `OhttpKeyPair` / `OhttpKeyConfig` with RFC 9458 §5 wire format (41 bytes)
  and DID Document `PAPObliviousHTTP` service publication. Passthrough mode preserved for
  direct connections when no `recipient_public_key` is configured.
- **pap-did**: `Service` struct and optional `service` field on `DidDocument` for W3C DID
  service endpoints (`PAPObliviousHTTP` and others). Backward-compatible with v1.0
  documents via `#[serde(default)]`.
- **pap-transport**: 9 unit tests covering OHTTP/HPKE error paths (`from_wire_bytes` too
  short, request too short, `fetch_key_config` missing/invalid service), `resolve_relay`
  branches, and `Clone` correctness for `OhttpServerDecryptor`.
- **pap-did**: 4 unit tests for `Service` JSON serialization, `skip_serializing_if`
  behavior on optional fields, `DidDocument` service field roundtrip, and backward
  compat with v1.0 documents lacking a `service` key.

## [0.7.2] - 2026-04-04

### Added

- **pap-federation**: Cursor-based pagination for federation peer sync queries. `QueryByAction` now accepts optional `cursor` and `page_size` fields; `QueryResponse` includes `next_cursor` and `has_more`. Server handler paginates by agent DID (lexicographic ordering, default 100 per page). Both native (`FederationClient`) and WASM (`FetchFederationClient`) clients gain `sync_action_paginated()` that loops until all pages are collected. Fully backward compatible — old clients/servers work unchanged via serde defaults.

## [0.8.0] - 2026-04-04

### Added

- **social recovery**: M-of-N Shamir Secret Sharing for the principal keypair (spec §13.5). You can now split your identity's seed into N shards and distribute them to trusted contacts — any M of those contacts can reconstruct your identity if you lose access. The scheme operates over GF(2^8) with CSPRNG-generated polynomial coefficients; 18 tests cover round-trips, tamper detection, replay prevention, and all error paths.
- **Papillon**: Four-step recovery setup wizard — accessible from the post-onboarding flow or on demand. Shows one shard at a time (previous shards removed from DOM before displaying the next), includes a copy button and a manifest download, and auto-advances after the identity loads if recovery is not yet configured.
- **Papillon**: Recovery reconstruction command — accepts M or more shard JSON blobs, verifies commitments and session nonces, checks reconstructed DID matches the active identity (if any), and persists the recovered seed to the authoritative profiles database.
- **pap-c**: C FFI bindings for social recovery — `pap_recovery_create_shards`, `pap_recovery_reconstruct`, and supporting helpers. Header in `crates/pap-c/include/pap.h`. Suitable for embedding in non-Rust runtimes (Python, Swift, Go).
- **pap-python**: Python bindings surface the new recovery API via PyO3.

### Changed

- **shamir**: `reconstruct()` now returns `Zeroizing<[u8; 32]>` so the recovered seed is zeroed on drop throughout its entire lifetime in the caller.
- **RecoveryShard**: `Drop` impl zeroizes `shard_bytes`, `session_nonce`, and `commitment` before heap release. `Debug` impl redacts those same fields — logging a shard via `{:?}` never emits partial secret material.
- **Papillon**: Recovered seed is written to `profiles_db` (the authoritative per-profile store) rather than the legacy key-value database — ensures the identity survives app restarts.
- **Papillon**: `create_recovery_shards` releases the seed read-lock before ceremony work begins, unblocking concurrent `switch_profile` calls.

### Fixed

- **shamir**: `lagrange_at_zero` precondition upgraded from `debug_assert` to `assert` — coordinate-length mismatch now panics in release builds rather than silently interpolating garbage.
- **shamir**: Reconstruction now rejects shards whose `index > total`, preventing silent wrong-value output.
- **Papillon**: TOCTOU race between DID identity check and signer installation eliminated by holding the write lock across the entire check-and-install sequence.
- **Papillon**: Input bounds enforced on `reconstruct_from_shards` — rejects more than 255 shards or individual shard strings larger than 8 KiB before any deserialization.
- **C FFI**: Stack seed buffer in `pap_recovery_create_shards` zeroized after ceremony; `pap_recovery_reconstruct` upper-bound guard added.

## [0.7.2] - 2026-04-05

### Added

- **pap-did**: `SignatureAlgorithm` enum (`#[non_exhaustive]`) with Ed25519 as the sole variant, providing metadata methods (multicodec prefix, JWS alg, verification key type, proof type) so adding a future algorithm is a mechanical, non-breaking change
- **pap-did**: Algorithm-aware DID resolution — `did_to_public_key_bytes_with_algorithm()` detects the algorithm from the multicodec prefix, `public_key_to_did_for_algorithm()` encodes keys for any supported algorithm
- **pap-did**: `UnsupportedAlgorithm` error variant for rejecting unknown multicodec prefixes
- **docs**: `algorithm-agility.md` documenting the migration path for adding post-quantum algorithms
- **pap-wasm**: Browser-native transport session (`TransportSession`) that drives the full 6-phase PAP handshake from JavaScript/TypeScript using the Fetch API. State-machine-enforced phase ordering prevents out-of-sequence calls. Auto-generates ephemeral session keypairs, co-signs receipts, and caches execution results. Wire-compatible with the native `AgentClient` (same REST endpoints, same `ProtocolMessage` JSON format).
- **pap-wasm**: `runHandshake()` convenience method that executes all 6 phases in a single async call.
- **pap-wasm**: Server-supplied session ID validation rejects path traversal characters before URL interpolation.
- **pap-wasm**: 12 wasm-bindgen tests covering state machine construction, phase ordering enforcement, and keypair uniqueness.
- **pap-wasm**: README with JS/TS usage examples, API reference, and build instructions.
- **pap-python**: Native `async/await` support for all 6 `AgentClient` transport methods — `present_token_async`, `exchange_did_async`, `send_disclosures_async`, `request_execution_async`, `exchange_receipt_async`, `close_session_async`. Python users can now `await` PAP protocol calls without blocking the asyncio event loop
- **pap-python**: PyO3 `experimental-async` feature enabled for direct Python coroutine compilation from Rust `async fn`
- **pap-python**: 23-test async test suite covering method existence, awaitable verification, connection error handling, `asyncio.gather` concurrency, and sync backward compatibility
- **pap-ts**: TypeScript reference implementation of PAP core (`@pap/core`). Pure TypeScript, works in Node.js 18+ and browsers. Covers identity (Ed25519 keypairs, `did:key` generation), mandates (issuance, delegation, chain verification, decay state machine), SD-JWT selective disclosure, session lifecycle (capability tokens, 6-phase handshake), transaction receipts (co-signing, attestations), and transport envelope signing. 103 tests via Vitest. Uses audited `@noble/ed25519` for all cryptography.
- **pap-ts**: Receipt state guard — `TransactionReceipt.fromSession()` now enforces session must be in Executed or Closed state
- **pap-ts**: HandshakeClient HTTP status checking — all 6 handshake phases now validate HTTP responses
- **papillon-extension**: SubtleCrypto Ed25519 signing — private keys are now non-extractable `CryptoKey` objects managed by the browser, never exposed in WASM memory or JS heap. Feature-detected at startup with automatic fallback to existing WASM path for browsers without Ed25519 SubtleCrypto support.
- **papillon-extension**: IndexedDB-backed key storage — `CryptoKey` objects stored via structured clone (no serialization), replacing AES-256-GCM encrypted seeds in `chrome.storage.local` for SubtleCrypto-capable browsers.
- **papillon-extension**: Automatic key migration — existing Ed25519 seeds are imported into SubtleCrypto and persisted in IndexedDB on first launch; legacy encrypted seeds are cleaned up after migration.
- **pap-core**: `signable_bytes()` and `set_signature_bytes()` on `Mandate` and `CapabilityToken` — enables external signing (e.g., browser SubtleCrypto) without exposing internal struct fields.
- **pap-wasm**: WASM bindings for `signableBytes()` and `setSignatureBytes()` on both `Mandate` and `CapabilityToken`.
- **ci**: Java JNA binding integration tests now run in CI — builds `libpap_c.so` and executes 85+ JUnit tests covering keypairs, mandates, scopes, decay states, sessions, and capability tokens via Gradle on every push and PR
- **pap-python**: 48 new negative-path and security-invariant tests for Session, CapabilityToken, and TransactionReceipt — covers invalid state transitions, tamper detection, expiry enforcement, insufficient signatures, ephemeral DID unlinkability, Mandate decay state progression, and delegation scope/TTL constraints
- **pap-python**: Shared conftest.py with pytest fixtures for keypairs, tokens, sessions, and mandates
- **pap-agents**: 10 new security-focused unit tests covering userinfo bypass, 0.0.0.0, file/data/javascript schemes, empty string, malformed URLs, IPv6 unique local, template variable safety, and octal IPv4 notation.

### Changed

- **pap-core**: All signable types (`Mandate`, `CapabilityToken`, `SessionAttestation`, `RecoveryMandate`, `PartialRecoverySignature`, `RevocationProof`) carry an `algorithm` field with `#[serde(default)]` for backward-compatible deserialization
- **pap-credential**: `VerifiableCredential::sign()` derives `proof_type` from `SignatureAlgorithm` instead of a hardcoded string; `SelectiveDisclosureJwt` carries an `algorithm` field
- **pap-proto**: JWS `sign_plaintext()` accepts `SignatureAlgorithm` and derives `alg` header from the enum; `verify_signed()` rejects unknown algorithms
- **pap-marketplace**: `AgentAdvertisement` carries an `algorithm` field with `#[serde(default)]`
- **pap-federation**: `PeerVouch` carries an `algorithm` field; `NotarySet` processes revocations with algorithm-aware `RevocationProof`
- **pap-webauthn**: `PrincipalSigner` trait gains an `algorithm()` default method returning Ed25519
- **pap-did**: `VerificationMethod` derives its key type from `SignatureAlgorithm` instead of a hardcoded string
- **docs/specification.md**: Section 16.1 updated from "algorithm agility is deferred" to documenting the `SignatureAlgorithm` field and forward-compatible negotiation
- All sign/verify tests parameterized by algorithm for future multi-algorithm expansion
- **pap-python**: You now get full IDE autocomplete and type checking out of the box — mypy, pyright, and Pylance discover the package's type stubs automatically via PEP 561 (`py.typed` marker)
- **pap-python**: `__init__.pyi` re-exports all 22 public symbols so autocomplete works at the `pap` package level (not just `pap._pap`)
- **pap-python**: Stub validation test suite (`test_stubs.py`) — verifies `.pyi` syntax, `py.typed` presence, and completeness against `__all__`
- **papillon-extension**: Hardened Content Security Policy from 2 directives to 9 — added `default-src 'none'` deny-by-default baseline, explicit `style-src`, `font-src`, `img-src`, `connect-src`, `base-uri`, and `form-action` directives. Extension pages can no longer load unauthorized resource types.
- **papillon-extension**: Replaced `Function()` constructor (eval-equivalent) in WASM loader with CSP-compliant `import(/* @vite-ignore */)` dynamic import. No `unsafe-eval` needed.
- **papillon-extension**: Firefox manifest CSP now derived from Chrome manifest instead of hardcoded duplicate, keeping both in sync automatically.
- **pap-python**: `AgentClient.inner` wrapped in `Arc` for safe sharing across async task boundaries — sync methods unchanged (auto-deref)
- **pap-python**: Added `pytest-asyncio>=0.23` to test dependencies

### Fixed

- **pap-agents**: Hardened `is_safe_url` SSRF validation against userinfo bypass — URLs with `user:pass@host` syntax previously bypassed host extraction, allowing requests to private/internal IPs. Also validates expanded URLs after `{query}` template substitution (defense in depth), rejects empty hosts, and documents DNS rebinding as a known limitation requiring network-layer controls.
- **papillon-extension**: Replaced `innerHTML = ""` with `replaceChildren()` at three call sites in handshake UI, aligning with the codebase's "never innerHTML" security policy.
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

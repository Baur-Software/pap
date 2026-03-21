# Changelog

All notable changes to PAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-03-21

### Added

- **papillion**: SQLite persistence layer for experience memory — episodes, agent profiles, retention policies, and settings stored across restarts via `rusqlite`
- **papillion**: Memory-informed agent selection — consults historical agent profiles to calibrate mandate TTL (3x headroom over avg duration) and disclosure sets (minimal refs after 5+ episodes)
- **papillion**: Agent profile aggregation with exponential moving average (EMA, alpha=0.2) — tracks success rate, quality, duration, and co-sign refusals per agent
- **papillion**: Principal keypair persistence — Ed25519 seed stored in SQLite settings table, auto-loaded on startup or generated on first launch
- **papillion**: JSON-LD semantic queries via `json_extract()` on Schema.org typed episode payloads
- **papillion**: `list_agent_profiles` Tauri command for frontend access to agent performance data
- **docs**: Memex(RL) architectural comparison — maps PAP's trust-bounded experience memory against Memex(RL) indexed retrieval patterns

### Changed

- **papillion**: `completed_runs` migrated from in-memory `Vec` to persistent SQLite episodes — scenario history survives app restarts
- **papillion**: `AppState` now holds `Arc<Database>` instead of `RwLock<Vec<ScenarioRunResult>>`
- **CLAUDE.md**: Updated with comprehensive project context — PAP is a protocol specification with Rust reference implementation, not SaaS. Added development standards (SOLID, comprehensive testing, no shortcuts, spec-first), core protocol concepts, and architecture documentation.

### Fixed

- **papillion**: Prevented panic on short DID/hash strings in step display — uses `.get(..N).unwrap_or()` instead of direct slice indexing

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

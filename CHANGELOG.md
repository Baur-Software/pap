# Changelog

All notable changes to PAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-21

### Added

- **papillion**: Multi-profile identity support — switch between multiple profiles (like browser profiles), each with its own DID and workspace
- **papillion**: Profile avatars with deterministic colors — visual distinction between profiles with semantic color palette (purple/teal/gold/coral/blue/rose)
- **papillion**: Profile manager in Settings — create, rename, delete, and switch profiles with last-used timestamps
- **papillion**: Profile dropdown in TopBar — quick access to all profiles with active profile indicator
- **papillion**: Complete state isolation per profile — profile switch resets canvas, registries, and orchestrator config for true workspace separation
- **docs**: Built-in LLM setup guide — quick reference for downloading TinyLLaMA and testing locally
- **docs**: Tauri resource directory quirk — comprehensive guide explaining platform-specific model bundling behavior (macOS/Windows/Linux)
- **docs**: Manual QA test plan — 20 comprehensive test cases covering profile creation, switching, isolation, persistence, and edge cases

### Changed

- **papillion**: Profile data now persisted in separate `profiles.db` registry alongside main database
- **papillion**: Seed zeroization hardened — `Zeroizing<[u8; 32]>` prevents sensitive material from lingering in memory

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

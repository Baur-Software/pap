# Changelog

All notable changes to PAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2026-03-21

### Fixed

- **papillion**: Episode recording now detects actual success/failure during data exchange, no longer hardcoding success on failed API calls — agent profile success rates are now accurate
- **papillion**: Quality metric now measures result completeness (0.0–1.0 based on result count/payload size) instead of mirroring success rate, enabling distinction between "1 result" vs "25 results"
- **papillion**: Minimal disclosure refs now computed as set intersection across all successful episodes, enabling progressive disclosure minimization instead of latest-episode overwrite
- **papillion**: Identity state is now atomic — signer and principal seed are protected by a single `RwLock<IdentityState>` to prevent race conditions where one is updated but not the other
- **papillion**: Canonical base64 encoding — imported identity seeds are decoded to bytes and re-encoded on export, eliminating issues with non-canonical user input

### Added

- **papillion**: `compute_quality()` function derives quality signals from result count in outcome details and payload size in result JSON
- **papillion**: `compute_minimal_disclosures()` function computes intersection across successful episode history, tracking truly minimal disclosure set
- **papillion**: Six integration tests for episode recording data fidelity (success flag detection, quality metrics, disclosure intersection)

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

- **papillion**: Fixed potential panic on short DID/hash strings in step display

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

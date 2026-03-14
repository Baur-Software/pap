# Changelog

All notable changes to PAP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

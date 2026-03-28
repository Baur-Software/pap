<div align="center">
  <img src="https://github.com/user-attachments/assets/51e636fd-d247-4ef8-aa56-9981ea79b504" alt="PAP Logo" width="200"/>
</div>

# PAP — Principal Agent Protocol

A principal-first, zero-trust agent negotiation protocol for the open web.

## The Problem

Existing agent protocols were designed for a single operator orchestrating tools on one machine, not for agents transacting across trust boundaries on behalf of different principals.

- **A2A** authenticates agents as platform entities. Privacy is an "opacity principle" — aspirational, not enforced. No mechanism for partial disclosure. Session residue is undefined.
- **MCP** connects models to tools. Its own spec states: "we cannot enforce these security principles at the protocol level." Designed for single-operator. Disclosure is monolithic.
- **ACP** handles REST-based agent interop. Thin trust layer. No cryptographic identity. No session ephemerality.
- **CrewAI, LangGraph, OpenAI Agents SDK** treat disclosure as an implementation detail. LangGraph's default is a shared scratchpad where every agent sees everything. No protocol mechanism to send less. When an API in the chain is compromised, the attacker gets full principal context.

**The unifying failure:** None enforce context minimization at the protocol layer. None define session ephemerality as a guarantee. Privacy is always an application problem, never a protocol problem.

## The Design

PAP makes it the protocol's problem.

The human principal is the root of trust. Every agent in a transaction carries a cryptographically verifiable mandate from that root. Sessions are ephemeral by design. Context disclosure is enforced by the protocol, not by policy. The cloud is a stateless utility invoked by agents, not a relationship that accumulates principal context.

**No new cryptography. No token economy. No central registry.**

## Why This Matters

**The Problem:** A compromise in one agent's tool chain becomes a compromise of your principal context. In every major framework — LangGraph, CrewAI, OpenAI Agents SDK, AutoGen — disclosure is monolithic. The agent gets a blob of context. There is no protocol mechanism to send less. When an API gets breached, the attacker gets everything the orchestrator knew about the principal: credit cards, address, travel history, medical conditions, financial data.

**The Structural Ceiling:** You cannot solve a disclosure problem with execution controls. Sandboxing constrains *what an agent can do*. It does not constrain *what it can see*. The protocol layer has no opinion on partial disclosure, so developers are left playing whack-a-mole: strip sensitive fields, the model rephrases them in responses; add output filters, the model finds new phrasings.

**PAP's Answer:** Protocol-enforced selective disclosure. An agent receives only the specific properties its mandate permits. The SD-JWT mechanism ensures undisclosed claims do not exist on the wire — not because a filter removed them, but because they were never transmitted. A compromised hotel API gets your check-in date, checkout date, and city. That is the blast radius. Not through defense-in-depth. Through protocol design.

Every session is ephemeral and unlinked to principal identity. Both parties sign receipts that record *which properties were disclosed*, never their values. The agent forgets everything at session close.

## Trust Model

```
Human Principal (device-bound keypair, root of trust)
  └─ Orchestrator Agent (root mandate, full principal context)
       └─ Downstream Agents (scoped task mandates)
            └─ Marketplace Agents (own principal chains)

Transactions are handshakes between two mandate chains, not two agents.
```

Five constraints enforced at the protocol level:

1. **Deny by default** — an agent can only do what its mandate explicitly permits
2. **Delegation cannot exceed parent** — scope and TTL are bounded, verified cryptographically
3. **Session DIDs are ephemeral** — unlinked to principal identity, discarded at close
4. **Receipts contain property references only** — never values
5. **Non-renewal is revocation** — mandates degrade progressively (Active → Degraded → ReadOnly → Suspended)

## Applications

### Papillon — Desktop Agent Canvas

One canvas. Many agents. Your rules. Papillon is a Tauri desktop app that lets you compose specialized AI agents — each scoped by a cryptographic mandate, each running in its own ephemeral session. Preview their plans, approve their actions, verify their results. No agent ever sees your full context.

- **Built-in LLM support** with on-demand model downloading
- **Canvas-based agent orchestration** with PAP mandates enforcing scope
- **WebAuthn device-bound identity** — your keys never leave your hardware
- **Deep-link protocol** (`pap://`, `pap+https://`, `pap+wss://`)

```bash
# Run from the repo root
cargo tauri dev -p papillon
```

[Documentation](https://baur-software.github.io/pap/papillon/) · [Source](apps/papillon/)

### Chrysalis — Federated Agent Registry

Publish your agent. Let any canvas find it. Chrysalis is a self-hostable federated registry node. Deploy one to make your agents discoverable, or form a mesh with other nodes via the federation protocol.

- **Axum + Leptos SSR** — server-rendered web UI, admin REST API, federation endpoints
- **SQLite or Postgres** — single-node or clustered deployments
- **Ed25519 signature verification** at ingest — unsigned or tampered advertisements rejected
- **TLS fingerprint pinning** — no CA dependency; DIDs are the trust root
- **Full-text search** via FTS5 / tsvector with paginated results

```bash
# Run locally (SQLite, no auth)
cargo run -p pap-registry --features ssr

# Docker
docker build -f apps/registry/Dockerfile -t pap-registry .
docker run -p 7890:7890 -v registry_data:/data \
  -e PAP_REGISTRY_ADMIN_TOKEN=change-me pap-registry
```

[Documentation](https://baur-software.github.io/pap/chrysalis.html) · [Source](apps/registry/) · [Detailed README](apps/registry/README.md)

## Quick Start

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test
```

## Protocol Stack

Built entirely on existing, standardized primitives:

| Layer | Standard | Purpose |
|-------|----------|---------|
| Identity | [WebAuthn](https://www.w3.org/TR/webauthn-3/) | Device-bound keypair generation |
| Identity | [W3C DIDs](https://www.w3.org/TR/did-core/) | Decentralized identifiers (`did:key`) |
| Credentials | [W3C VCs](https://www.w3.org/TR/vc-data-model-2.0/) | Mandate envelope |
| Disclosure | [SD-JWT](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.txt) | Selective claim disclosure |
| Vocabulary | [Schema.org](https://schema.org) | Capability and action types |
| Data | [JSON-LD](https://www.w3.org/TR/json-ld11/) | Structured linked data |
| Privacy | [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458) | Cloud request unlinkability |
| Transport | HTTP/JSON | 6-phase session handshake |
| Federation | HTTP/JSON | Cross-registry sync, announce, peer discovery |

## Crate Structure

```
pap/
  crates/
    pap-did/              # DID generation, session keypairs (did:key, Ed25519)
    pap-core/             # Mandate, scope, session, receipt, extensions
    pap-credential/       # W3C VC envelope, SD-JWT selective disclosure
    pap-credential-store/ # Encrypted vault for principal seeds, VCs, continuity tokens
    pap-marketplace/      # Agent advertisement, registry, discovery
    pap-agents/           # Shared agent implementations (AgentExecutor trait)
    pap-proto/            # Protocol message types and envelope
    pap-transport/        # HTTP client/server for 6-phase handshake
    pap-federation/       # Cross-registry sync, announce, peer exchange
    pap-webauthn/         # WebAuthn signer abstraction + software fallback
    pap-c/                # C FFI bindings (cdylib + staticlib)
    pap-wasm/             # WebAssembly bindings (@pap/sdk npm package)
    pap-python/           # Python PyO3 bindings
    papillon-shared/      # Shared models between Papillon frontend and backend
  apps/
    registry/             # Hostable federated PAP registry (Axum + Leptos SSR, SQLite/Postgres)
    papillon/             # Desktop reference implementation (Tauri)
  bindings/
    cpp/                  # C++ RAII header-only wrapper (pap.hpp)
    csharp/               # .NET 8 C# P/Invoke bindings with SafeHandle RAII
    java/                 # JNA-based Java bindings (io.pap.*)
```

### pap-did

- `PrincipalKeypair` — Ed25519 keypair with `did:key` derivation. Root of trust.
- `SessionKeypair` — Ephemeral, single-use, unlinked to principal identity.
- `DidDocument` — W3C DID Core document. Contains no personal information.

### pap-core

- `Scope` — Schema.org action references, deny-by-default.
- `Mandate` — Hierarchical delegation with chain verification. Scope/TTL bounded by parent. Optional `payment_proof`.
- `DecayState` — Active / Degraded / ReadOnly / Suspended. Progressive scope reduction.
- `CapabilityToken` — Single-use, bound to target DID + action + nonce. Not a billable unit.
- `Session` — State machine: Initiated → Open → Executed → Closed.
- `TransactionReceipt` — Co-signed by both parties. Property references only.
- `ContinuityToken` — Encrypted vendor state. Principal controls TTL and deletion.
- `AutoApprovalPolicy` — Principal-authored policies for micro-transactions.

### pap-credential

- `VerifiableCredential` — W3C VC 2.0 envelope wrapping mandate payloads.
- `SelectiveDisclosureJwt` — SD-JWT. Over-disclosure structurally prevented.

### pap-credential-store

- `Vault<S>` — Encrypted-at-rest storage for PAP protocol material. Two-layer encryption: master password → Argon2id → AES-256-GCM vault key.
- `VaultStore` trait — Pluggable backend (SQLite shipped, IndexedDB planned for browser extension).
- `VaultSigner` — `PrincipalSigner` implementation backed by encrypted vault. Drop-in replacement for `SoftwareSigner`.
- Four item types: `PrincipalSeed`, `ContinuityToken`, `VerifiableCredential`, `NotaryDesignation`.
- Auto-lock with configurable timeout. Vault key zeroized on lock.

### pap-agents

- `AgentExecutor` trait — Simplified 2-method interface (`meta()` + `execute(query)`) for agent implementations.
- `SimpleAgent<E>` wrapper — Adapts any `AgentExecutor` into the full 6-phase `AgentHandler` protocol.
- 14 built-in agents including `CredentialStoreExecutor` for vault operations via Schema.org JSON-LD.
- Shared across Papillon and Chrysalis — agents are defined once, used everywhere.

### pap-marketplace

- `AgentAdvertisement` — Signed JSON-LD. Capabilities, disclosure requirements, return types.
- `MarketplaceRegistry` — Query by action type, filter by satisfiable disclosure.

### pap-transport

- `AgentServer` — Axum HTTP server exposing 6 protocol phase endpoints.
- `AgentClient` — HTTP client driving the handshake from the initiator side.
- `AgentHandler` trait — Transport-agnostic protocol logic. Implement once, work with any transport.
- 6-phase protocol: Token → DID Exchange → Disclosure → Execution → Receipt → Close.
- **Transport-agnostic design:** The protocol is independent of HTTP. Custom transports (WebSocket, gRPC, Bluetooth, etc.) implement the same handler. See [Transport Bindings](docs/TRANSPORT_BINDINGS.md).

### pap-federation

- `FederatedRegistry` — Local + remote agent tracking with content-hash dedup.
- `FederationServer` — HTTP endpoints for query, announce, peer discovery.
- `FederationClient` — Pull sync by action type, push announcements, peer exchange.

### pap-c

- Stable C FFI layer (cdylib + staticlib) exposing all PAP primitives via opaque handles.
- Thread-local last-error storage for cross-language error propagation.
- Defensive hardening: null pointer validation on array counts and per-element dereferencing.
- `pap_mandate_sync_decay_state` helper for automatic Active→ReadOnly TTL-expiry handling.

### pap-wasm

- WebAssembly bindings via wasm-bindgen for JavaScript/TypeScript consumers.
- npm package: `@pap/sdk` with full PAP core API (no transport layer).
- Type-safe WASM wrapper for mandate verification, scope checking, and session state machines.

### pap-python

- PyO3-based Python bindings for all PAP primitives.
- Full access to DID generation, mandate delegation, and session lifecycle.

## Language Bindings

PAP exposes stable FFI layers for multiple languages:

| Language | Package | Transport | Notes |
|----------|---------|-----------|-------|
| Rust | `pap-*` crates | ✓ Built-in | Native async support |
| Python | `pap-python` | PyO3 | Available via PyPI |
| JavaScript/TypeScript | `@pap/sdk` | wasm-bindgen | WASM-based, no transport |
| C/C++ | `libpap` + `pap.hpp` | cdylib/staticlib | Header-only wrapper, RAII semantics |
| C# | `pap-dotnet` | P/Invoke | .NET 8+, SafeHandle RAII |
| Java | `pap-java` | JNA | AutoCloseable handles, full enum support |

For language bindings, see `crates/pap-c`, `crates/pap-wasm`, `crates/pap-python`, and `bindings/`.

## Why a Federated Registry?

An open agent network needs a registry for discovery, pre-session disclosure matching, payment negotiation, trust at the edge, accountability, and operator sovereignty. Chrysalis provides all six — without a central authority. See the [Chrysalis documentation](https://baur-software.github.io/pap/chrysalis.html) and [registry README](apps/registry/README.md) for the full rationale and API reference.

## How PAP Differs

| Feature | A2A | MCP | ACP | PAP |
|---------|-----|-----|-----|-----|
| **Trust Root** | Platform entity | Model + tools | Enterprise gateway | Human principal |
| **Protocol Enforces Disclosure?** | No ("opacity principle") | No (spec says aspirational) | No | Yes (SD-JWT structural guarantee) |
| **Session Ephemerality** | No | Stateful | Stateless option | Ephemeral DIDs, keys always discarded |
| **Selective Disclosure** | No (all or nothing) | No (all or nothing) | No (all or nothing) | Yes (per-field, cryptographic) |
| **Mandate Chain Verification** | No | No | No | Yes (recursive scope/TTL bounds) |
| **Agent-to-Agent Negotiation** | Yes | No (tool access only) | Yes | Yes |
| **Economic Primitives** | No | No | No | Ecash / Lightning proofs, receipts |
| **Marketplace Discovery** | Agent Cards (centralized) | None | HTTP (centralized) | Federated, federated (Chrysalis) |
| **Audit Trail** | No | No | No | Co-signed receipts (property refs only) |
| **Multi-Language Support** | No | Limited | Limited | Rust, Python, JS/TS, C, C#, Java |

## Performance

Core protocol operations benchmarked with [Criterion.rs](https://github.com/bheisler/criterion.rs). CI fails if any p50 regresses >20% vs baseline.

| Operation | Target (p50) |
|-----------|-------------|
| Ed25519 keypair generation | < 1 ms |
| `did:key` derivation | < 0.5 ms |
| Mandate creation + sign | < 2 ms |
| Mandate chain verification (depth 3) | < 5 ms |
| SD-JWT issue (5 claims) | < 3 ms |
| SD-JWT verify + disclose (3 of 5) | < 2 ms |
| Session open (full lifecycle, loopback) | < 20 ms |
| Receipt creation + co-sign | < 3 ms |
| Federation announce (single peer) | < 50 ms |

```bash
# Run benchmarks
cargo bench -p pap-bench

# Check for regressions against baseline
bash benches/check_regression.sh

# Update baseline with current results
bash benches/check_regression.sh --update-baseline
```

## Protocol Extensions

Extensions evaluated against the capture test: does this reduce or expand the attack surface for incumbent platform capture?

- **Privacy-Preserving Payment** — Ecash / Lightning proofs. Vendor cannot identify payer.
- **Continuity Tokens** — Encrypted vendor state, principal-controlled TTL. Delete to sever.
- **Auto-Approval Tiers** — Principal-authored policies. Cannot exceed mandate scope.
- **Hardware-Constrained Principals** — Confidential computing fallback. Spec is honest about the trust assumption.
- **Institutional Recovery** — M-of-N social recovery via banks/notaries. No single points. No platform operators.

## The Capture Test

Any proposal that routes principal context through infrastructure owned by incumbent platforms is out of scope, regardless of the cryptographic framing. Every major internet protocol that started with user sovereignty has been captured by the entities with the largest infrastructure footprint.

**Explicit non-goals:** token economy compatibility; enclave-as-equivalent-to-local; identity recovery through platform operators; payment mechanisms linkable to principal identity; central registries; runtime scope expansion; arbitrary code execution in the orchestrator; any extension that trades trust guarantees for adoption ease.

Good feedback makes the protocol harder to capture.

## Blog Posts

- [Your Agent Works for a Platform. It Should Work for You.](https://baursoftware.com/your-agent-works-for-a-platform-it-should-work-for-you/) — Protocol introduction + code walkthrough
- [Show Me the Agents: PAP in Practice](https://baursoftware.com/show-me-the-agents-pap-in-practice/) — Real-world scenarios + docker-compose examples
- [The Tollbooth Model Is Over](https://baursoftware.com/the-tollbooth-model-is-over/) — Economic context

## Documentation

- **[Baur Software](https://baur-software.github.io/pap/)** — Project home
- **[PAP Protocol](https://baur-software.github.io/pap/pap/)** — Architecture specification, cryptographic model, and protocol design
- **[Papillon](https://baur-software.github.io/pap/papillon/)** — Desktop app documentation
- **[Chrysalis](https://baur-software.github.io/pap/chrysalis.html)** — Federated registry documentation
- **[Transport Bindings](docs/TRANSPORT_BINDINGS.md)** — HTTP, WebSocket, gRPC, IoT, and custom transport protocols
- **[Design System](DESIGN.md)** — Visual design and component conventions

## License

MIT OR Apache-2.0

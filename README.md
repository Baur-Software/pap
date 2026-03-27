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

## Quick Start

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test
```

For interactive demos, see [Papillon](https://baur-software.github.io/pap/papillon/).

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
- Shared across Papillion and Chrysalis — agents are defined once, used everywhere.

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

## Chrysalis: Hostable Federated Registry

`apps/registry/` is **Chrysalis**, a standalone, self-hosted federated PAP registry. Deploy one node to make your agents discoverable, or form a mesh with other nodes via the federation protocol.

```bash
# Run locally (SQLite, no auth)
cargo run -p pap-registry --features ssr

# Docker (with persistent volume and admin token)
docker build -f apps/registry/Dockerfile -t pap-registry .
docker run -p 7890:7890 -v registry_data:/data \
  -e PAP_REGISTRY_ADMIN_TOKEN=change-me pap-registry
```

Key characteristics:
- **Self-hosted registry node** — Each instance is a DID-bound agent discoverable by peers
- **Federated discovery** — Mesh multiple registry nodes; agents propagate across the network via announce/sync
- **TLS fingerprint pinning** — No CA dependency; each node has a self-signed cert bound to its DID
- **Ed25519 signature verification** — Unsigned or tampered agent advertisements rejected at ingest
- **Admin REST API** (`/api/*`) + Leptos SSR web UI at `/`
- **Full-text search** — SQLite FTS5 or Postgres tsvector with paginated results
- **Multi-backend support** — SQLite for single-node, Postgres for clustered deployments

### Why a Registry?

An open agent network needs a registry for six distinct reasons: discovery, pre-session disclosure matching, payment negotiation, trust at the edge, accountability, and operator sovereignty.

**Discovery without a central directory**

An agent advertising `schema:ReserveAction` shouldn't require a platform-controlled directory to be found. Chrysalis nodes store signed `AgentAdvertisement` records indexed by Schema.org action type and free-text capability description. An orchestrator looking for a hotel-booking agent queries its local registry — not a platform API — and receives a list of candidates along with their disclosure requirements. Because the federation protocol propagates advertisements across nodes via push/pull sync, no single node is authoritative. The network discovers its topology from the bottom up.

Full-text search over FTS5/tsvector means any node in the mesh can answer capability queries without a custom routing layer or a crawl-the-web index.

**Pre-session disclosure matching**

Before initiating a session, an orchestrator can inspect a candidate's `AgentAdvertisement` to see exactly which SD-JWT claims the agent requires. If the principal's current mandate doesn't cover those fields, the orchestrator can skip that candidate — without establishing a session, exchanging DIDs, or transmitting any context at all. Unnecessary exposure during candidate evaluation is eliminated at the query stage, not the session stage.

**Payment as a first-class protocol primitive**

Agents in an open network need to charge for execution. PAP's `Mandate` includes an optional `payment_proof` field — an ecash token or Lightning preimage that the service-side agent verifies before processing the request. The registry is where an agent *advertises* its payment terms: denomination, mechanism, and whether the caller needs a prior proof-of-funds before the session begins.

Ecash tokens are unlinkable to the principal identity. The vendor learns a transaction occurred but not who paid. This is not a payment processor — it is a mechanism for agents to negotiate micro-transactions without routing through a platform's billing infrastructure. The registry publishes the terms; the session handshake carries the proof; neither touches a centralized payment rail.

**Trust at the edge, not at the center**

Chrysalis nodes don't require a trusted third party to validate agent identity. Ed25519 signature verification happens at ingest: an advertisement that wasn't signed by the claiming DID's key is rejected with `422`. Compromise of one peer node cannot inject forged agents into the mesh because every downstream node re-verifies on receipt. TLS fingerprint pinning (TOFU, no CA dependency) means peer connections are authenticated by DID, not by a certificate authority a platform operator controls.

**Accountability without exposure**

The registry creates a verifiable record of which agents exist and what they claim to do. Co-signed `TransactionReceipt`s — containing property references only, never values — are the per-session record of what was disclosed and executed. Registry advertisements plus session receipts produce a complete audit trail: what the agent advertised, what the principal authorized, and what categories of data were exchanged. No values appear anywhere in this chain.

This separates accountability from surveillance. You can prove a transaction occurred and what types of data it touched. You cannot reconstruct the data itself.

**Operator sovereignty**

Any organization can run its own Chrysalis node. Agents do not need permission from a platform to be discoverable. There is no central index to capture, no API key to revoke, and no terms-of-service gate on discovery. A company running its own registry node can federate selectively — peering with trusted nodes while keeping internal agents off the public mesh entirely. The federation protocol is the same in both cases; the trust boundary is operator-defined.

See [apps/registry/README.md](apps/registry/README.md) for full documentation.

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

- **[PAP v0.1 Architecture Specification](https://baursoftware.com/pap)** — Full protocol design and cryptographic model
- **[Transport Bindings](docs/TRANSPORT_BINDINGS.md)** — How PAP works across HTTP, WebSocket, gRPC, IoT, and custom transport protocols
- **[Design System](DESIGN.md)** — Visual design and component conventions

## License

MIT OR Apache-2.0

# PAP — Principal Agent Protocol

A principal-first, zero-trust agent negotiation protocol for the open web.

## The Problem

Every agent protocol in production today — A2A, MCP, ACP, AGNTCY — was designed to serve platform operators, not human principals.

- **A2A** authenticates agents as platform entities. Privacy is an "opacity principle" — aspirational, not enforced. No context minimization. No session ephemerality.
- **MCP** connects models to tools. It is not an agent-to-agent negotiation protocol. Its own spec acknowledges it "cannot enforce these security principles at the protocol level."
- **ACP** handles REST-based agent interop. Thin trust layer. No cryptographic identity.
- **CrewAI, LangGraph, OpenAI Agents SDK** treat privacy as an implementation detail. LangGraph's default is a shared scratchpad where every agent sees everything.

None enforce context minimization at the protocol level. None define session ephemerality as a guarantee. None have economic primitives. Privacy is always somebody else's problem.

## The Design

PAP makes it the protocol's problem.

The human principal is the root of trust. Every agent in a transaction carries a cryptographically verifiable mandate from that root. Sessions are ephemeral by design. Context disclosure is enforced by the protocol, not by policy. The cloud is a stateless utility invoked by agents, not a relationship that accumulates principal context.

**No new cryptography. No token economy. No central registry.**

## Why Should I Care?

You searched for a stroller once. Now every website thinks you're pregnant. For six months. That's one query, with a human behind a browser. Now imagine AI agents making hundreds of queries on your behalf — every one leaking context to platforms that build profiles, adjust prices, and sell your behavioral data to brokers you've never heard of.

PAP ensures your agent discloses only what you explicitly permit, to the specific service that needs it, for the duration of a single session, with a signed receipt proving what happened.

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

# Core protocol examples
cargo run --bin search               # Zero-disclosure search
cargo run --bin travel-booking       # SD-JWT selective disclosure
cargo run --bin delegation-chain     # 4-level trust hierarchy
cargo run --bin payment              # Ecash + auto-approval + continuity

# Transport & federation
cargo run --bin networked-search     # Full 6-phase handshake over HTTP
cargo run --bin federated-discovery  # Cross-registry agent discovery
cargo run --bin webauthn-ceremony    # Device-bound key generation
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
    pap-did/          # DID generation, session keypairs (did:key, Ed25519)
    pap-core/         # Mandate, scope, session, receipt, extensions
    pap-credential/   # W3C VC envelope, SD-JWT selective disclosure
    pap-marketplace/  # Agent advertisement, registry, discovery
    pap-proto/        # Protocol message types and envelope
    pap-transport/    # HTTP client/server for 6-phase handshake
    pap-federation/   # Cross-registry sync, announce, peer exchange
    pap-webauthn/     # WebAuthn signer abstraction + software fallback
  examples/
    search/              # Zero-disclosure end-to-end PoC
    travel-booking/      # SD-JWT selective disclosure
    delegation-chain/    # 4-level mandate hierarchy
    payment/             # Ecash + auto-approval + continuity tokens
    networked-search/    # HTTP transport handshake
    federated-discovery/ # Cross-registry federation
    webauthn-ceremony/   # Device-bound key generation
    local-ai-assistant/  # Docker Compose: Ollama + SearXNG + PAP
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

### pap-marketplace

- `AgentAdvertisement` — Signed JSON-LD. Capabilities, disclosure requirements, return types.
- `MarketplaceRegistry` — Query by action type, filter by satisfiable disclosure.

### pap-transport

- `AgentServer` — Axum HTTP server exposing 6 protocol phase endpoints.
- `AgentClient` — HTTP client driving the handshake from the initiator side.
- 6-phase protocol: Token → DID Exchange → Disclosure → Execution → Receipt → Close.

### pap-federation

- `FederatedRegistry` — Local + remote agent tracking with content-hash dedup.
- `FederationServer` — HTTP endpoints for query, announce, peer discovery.
- `FederationClient` — Pull sync by action type, push announcements, peer exchange.

## Examples

Seven examples demonstrate the full protocol surface. Each exercises features the others do not.

### `search` — Zero-Disclosure Transaction

The simplest transaction that proves the trust model works: a web search with zero personal disclosure.

12 protocol steps. Principal generates keypair → issues mandate → marketplace query → capability token → delegation → token presentation → session DID exchange → zero disclosure → execution → co-signed receipt → session close → receipt audit.

```bash
cargo run --bin search
```

### `travel-booking` — Selective Disclosure

A flight booking requiring personal context. Proves disclosure controls work under real constraints.

- SD-JWT: 2 of 4 claims revealed (name + nationality). Email + telephone cryptographically withheld.
- Marketplace filtering: agents requiring more than the mandate permits are excluded before mandate issuance.
- Receipt: property references only. "Alice Baur" and "US" never appear.

```bash
cargo run --bin travel-booking
```

### `delegation-chain` — Hierarchical Trust

4-level mandate hierarchy. Scope narrows and TTL shrinks at each level.

| Level | Agent | Scope | TTL |
|-------|-------|-------|-----|
| 0 | Human Principal | (root) | — |
| 1 | Orchestrator | Search, Reserve(Flight), Reserve(Lodging), Pay | 4h |
| 2 | Trip Planner | Search, Reserve(Flight) | 3h |
| 3 | Booking Agent | Reserve(Flight) | 2h |

Three rejected delegations prove the constraints hold. Decay state transitions demonstrate progressive degradation.

```bash
cargo run --bin delegation-chain
```

### `payment` — Protocol Extensions

Chaumian ecash payment proof (vendor cannot identify payer), value-capped auto-approval ($12.99 auto-approved below $20 threshold), and continuity tokens (90-day principal-controlled TTL, delete to sever).

```bash
cargo run --bin payment
```

### `networked-search` — HTTP Transport

Same protocol invariants as the in-memory search, but over HTTP. Single binary spawns an Axum server on a random port, then the client drives the 6-phase handshake. Proves the transport is a thin wrapper — it doesn't change the trust model.

```bash
cargo run --bin networked-search
```

### `federated-discovery` — Marketplace Federation

Two independent registries on different ports. Registry A has a search agent. Registry B has a payment agent. Federation sync makes search agents discoverable through Registry B. Push announcements, content-hash dedup, peer discovery.

```bash
cargo run --bin federated-discovery
```

### `webauthn-ceremony` — Device-Bound Keys

WebAuthn-based key generation with mock authenticator for testing. Demonstrates the production path for device-bound principal keypairs.

```bash
cargo run --bin webauthn-ceremony
```

### `local-ai-assistant` — Docker Compose

A complete local AI assistant: Ollama (local LLM) + SearXNG (private search) + PAP marketplace + three provider agents + orchestrator + receipt viewer. Your prompts never leave your machine. External tool use goes through PAP's full handshake with selective disclosure.

```bash
cd examples/local-ai-assistant
docker compose up -d
docker exec ollama ollama pull mistral
curl http://localhost:9010/ask -d '{"query": "What is the weather in Seattle?"}'
curl http://localhost:9090/receipts  # See what was disclosed
```

## What This Replaces

| Concern | A2A | MCP | ACP | PAP |
|---------|-----|-----|-----|-----|
| Context minimization | No | No | No | SD-JWT per interaction |
| Session ephemerality | No | Stateful | Stateless option | Ephemeral DIDs, keys discarded |
| Field-level disclosure | No | No | No | SD-JWT selective claims |
| Cryptographic scope enforcement | No | No | No | Mandate chain verification |
| Agent-to-agent negotiation | Yes | No (tool access) | Yes | Yes |
| Privacy-preserving payment | No | No | No | Ecash / Lightning proofs |
| Marketplace discovery | Agent Cards | None | HTTP | Federated, disclosure-filtered |
| Audit trail | No | No | No | Co-signed receipts |
| Principal control | Platform | User (stated) | Enterprise | Cryptographic mandate |

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

## Specification

See the [PAP v0.1 Architecture Specification](https://baursoftware.com/pap) for the full protocol design.

## License

MIT OR Apache-2.0

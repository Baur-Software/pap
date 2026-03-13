# PAP — Principal Agent Protocol

A principal-first, zero-trust agent negotiation protocol for the open web.

## The Problem

Every agent-to-agent protocol currently in development — A2A, ACP, AgentConnect, MCP — was designed to serve platform operators, not human principals. The trust models are thin, context minimization is voluntary, session residue is undefined, and the economic model underneath each protocol is cloud compute metering.

## The Design

PAP is designed from the opposite direction. The human principal is the root of trust. Every agent in a transaction carries a cryptographically verifiable mandate from that root. Sessions are ephemeral by design. Context disclosure is enforced by the protocol, not by policy. The cloud is a stateless utility invoked by agents, not a relationship that accumulates principal context.

**No new cryptography. No token economy. No central registry.**

## Trust Model

```
Human Principal (device-bound keypair, root of trust)
  └─ Orchestrator Agent (root mandate, full principal context)
       └─ Downstream Agents (scoped task mandates)
            └─ Marketplace Agents (own principal chains)

Transactions are handshakes between two chains, not two agents.
```

- **Deny by default** — an agent can only do what its mandate explicitly permits
- **Delegation cannot exceed parent** — scope and TTL are bounded by the issuing mandate
- **Session DIDs are ephemeral** — unlinked to principal identity, discarded at close
- **Receipts contain property references only** — never values
- **No platform stores principal context**

## Protocol Stack

PAP is built entirely on existing, standardized primitives:

| Layer | Standard | Purpose |
|-------|----------|---------|
| Identity | [WebAuthn](https://www.w3.org/TR/webauthn-3/) | Device-bound keypair generation |
| Identity | [W3C DIDs](https://www.w3.org/TR/did-core/) | Decentralized identifiers |
| Credentials | [W3C VCs](https://www.w3.org/TR/vc-data-model-2.0/) | Mandate envelope |
| Disclosure | [SD-JWT](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.txt) | Selective claim disclosure |
| Vocabulary | [Schema.org](https://schema.org) | Capability and action types |
| Data | [JSON-LD](https://www.w3.org/TR/json-ld11/) | Structured linked data |
| Privacy | [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458) | Cloud request unlinkability |

## Crate Structure

```
pap/
  crates/
    pap-did/          # DID document generation, session keypairs (did:key, Ed25519)
    pap-core/         # Mandate, scope, session, receipt primitives
    pap-credential/   # W3C VC envelope, SD-JWT selective disclosure
    pap-marketplace/  # Agent advertisement schema, registry, discovery
  examples/
    search/           # End-to-end PoC: principal -> orchestrator -> search agent
```

### pap-did

`PrincipalKeypair` — Ed25519 keypair with `did:key` derivation. Root of trust.
`SessionKeypair` — Ephemeral, single-use, unlinked to principal identity.
`DidDocument` — W3C DID Core document. Contains no personal information.

### pap-core

`Scope` — Schema.org action references, deny-by-default. Schema.org describes the what; the protocol governs under what terms.
`Mandate` — Hierarchical delegation with chain verification. Scope cannot exceed parent. TTL cannot exceed parent.
`DecayState` — Active / Degraded / ReadOnly / Suspended. Progressive scope reduction on non-renewal.
`CapabilityToken` — Single-use, bound to target DID + action + nonce. Not a billable unit.
`Session` — State machine: Initiated / Open / Executed / Closed.
`TransactionReceipt` — Co-signed by both parties. Property references only, never values.

### pap-credential

`VerifiableCredential` — W3C VC Data Model 2.0 envelope wrapping mandate payloads.
`SelectiveDisclosureJwt` — SD-JWT for the disclosure exchange in the session handshake. Over-disclosure is structurally prevented.

### pap-marketplace

`AgentAdvertisement` — Signed JSON-LD using Schema.org types. Describes capabilities, disclosure requirements, return types.
`MarketplaceRegistry` — Local registry for the PoC. Query by action type, filter by satisfiable disclosure requirements.

## Quick Start

```bash
# Clone and test
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test

# Run the search example
cargo run --bin search
```

## The Search Example

The search example demonstrates the full protocol flow with zero personal disclosure — the simplest meaningful transaction that proves the trust model works end to end.

1. Principal generates an Ed25519 keypair and DID document
2. Principal issues a root mandate to the orchestrator (scope: `schema:SearchAction`)
3. Orchestrator queries the local marketplace registry for a search agent
4. Orchestrator mints a capability token bound to the search agent's DID
5. Orchestrator delegates a task mandate to an initiating agent
6. Initiating agent presents the capability token to the search agent
7. Search agent verifies the token — target DID, nonce, signature chain
8. Both agents exchange ephemeral session DIDs (unlinked to principal identity)
9. Initiating agent discloses nothing — search requires no personal context
10. Search agent executes and returns structured results
11. Both agents co-sign a transaction receipt (property refs only, no values)
12. Session closes — ephemeral keys discarded, nonce consumed

The receipt is auditable by both principals. No platform stored anything.

## What This Replaces

**A2A** authenticates agents as platform entities, not as mandate-holders for human principals.
**ACP** focuses on enterprise workflow interoperability. The principal is the enterprise, not the individual.
**MCP** handles tool-use for a single agent session. It is not a negotiation protocol between agents representing different principals.

None enforce context minimization at the protocol level. None define session ephemerality as a protocol guarantee. All are compatible with token economy monetization.

PAP has no token economy. The capability token is a single-use cryptographic proof, not a billable unit. When inference runs locally and sessions are ephemeral, there is no persistent relationship to monetize.

## Specification

See the [PAP v0.1 Architecture Specification](https://baursoftware.com/pap) for the full protocol design.

## License

MIT OR Apache-2.0

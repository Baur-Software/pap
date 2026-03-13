# Your Agent Works for a Platform. It Should Work for You.

Every agent-to-agent protocol currently in development was designed to serve platform operators, not human principals.

A2A authenticates agents as platform entities. ACP focuses on enterprise workflow interoperability where the principal is the enterprise, not the individual. MCP handles tool-use for a single agent session — it is not a negotiation protocol between agents representing different principals. AgentConnect optimizes for deployment topology, not trust topology.

None of them enforce context minimization at the protocol level. Disclosure is implementation-dependent. None define session ephemerality as a protocol guarantee. All are compatible with token economy monetization. None structurally prevent it.

The trust models are thin. The context controls are voluntary. The session residue is undefined. And the economic model underneath each protocol is cloud compute metering — the same model that turned every previous generation of open standards into a funnel for platform lock-in.

We built something different.

## The Principal Agent Protocol

[PAP](https://github.com/Baur-Software/pap) is designed from the opposite direction. The human principal is the root of trust. Every agent in a transaction carries a cryptographically verifiable mandate from that root. Sessions are ephemeral by design. Context disclosure is enforced by the protocol, not by policy. The cloud is a stateless utility invoked by agents, not a relationship that accumulates principal context.

No new cryptography. No token economy. No central registry.

The repo is open source, written in Rust, and you can clone it and run the end-to-end proof of concept right now.

## The Trust Model

```
Human Principal (device-bound keypair, root of trust)
  └─ Orchestrator Agent (root mandate, full principal context)
       └─ Downstream Agents (scoped task mandates)
            └─ Marketplace Agents (own principal chains)
```

Transactions are handshakes between two mandate chains, not two agents. The orchestrator is the only agent that knows who you are. Every downstream agent knows only what its mandate explicitly permits.

Five constraints are enforced at the protocol level, not the implementation level:

1. **Deny by default.** An agent can only do what its mandate explicitly permits. No scope means no action.
2. **Delegation cannot exceed parent.** A child mandate's scope is bounded by its parent's scope. A child's TTL cannot exceed its parent's TTL. This is verified cryptographically, not by policy.
3. **Session DIDs are ephemeral.** Both agents generate single-use keypairs for each session. These are not linked to any persistent identity. When the session closes, the keys are discarded.
4. **Receipts contain property references only.** A transaction receipt records *what types* of data were disclosed — never the values. Both principals can audit the record. No platform stores it.
5. **Non-renewal is revocation.** A mandate that isn't renewed doesn't need a revocation notice. It degrades progressively — Active, Degraded, ReadOnly, Suspended — and then it stops. The principal sees the degradation, not a surprise cutoff.

## Built on Standards That Already Exist

PAP uses no novel cryptographic primitives. The entire protocol stack is built on existing, standardized specifications maintained by bodies without platform capture:

| Layer | Standard | Purpose |
|-------|----------|---------|
| Identity | WebAuthn | Device-bound keypair generation |
| Identity | W3C DIDs | Decentralized identifiers (`did:key`) |
| Credentials | W3C VC Data Model 2.0 | Mandate envelope |
| Disclosure | SD-JWT (IETF draft-08) | Selective claim disclosure in session handshake |
| Vocabulary | Schema.org | Capability and action type references |
| Data | JSON-LD | Structured linked data for advertisements |
| Privacy | Oblivious HTTP (RFC 9458) | Cloud request unlinkability |

Schema.org describes the *what*. The protocol governs *under what terms*. These are kept strictly separate — no Schema.org extensions, no vocabulary pollution.

## The Implementation

The Rust implementation ships as four crates in a Cargo workspace:

**`pap-did`** — `PrincipalKeypair` (Ed25519, `did:key` derivation), `DidDocument` (W3C DID Core), `SessionKeypair` (ephemeral, unlinked to principal identity).

**`pap-core`** — The protocol primitives. `Scope` with deny-by-default semantics. `Mandate` with hierarchical delegation, chain verification, and progressive decay. `CapabilityToken` — single-use, bound to target DID + action + nonce. `Session` state machine (Initiated → Open → Executed → Closed). `TransactionReceipt` — co-signed by both parties, property references only.

**`pap-credential`** — `VerifiableCredential` envelope wrapping mandate payloads per W3C VC Data Model 2.0. `SelectiveDisclosureJwt` for the disclosure exchange in the session handshake — over-disclosure is structurally prevented, not just discouraged.

**`pap-marketplace`** — `AgentAdvertisement` (signed JSON-LD, Schema.org typed). `MarketplaceRegistry` (local file-based for the PoC, federated later). Query by Schema.org action type, filter by satisfiable disclosure requirements.

63 tests. All green. The test suite covers scope containment, mandate chain verification, delegation boundary enforcement, token replay prevention, session state machine transitions, receipt co-signing, selective disclosure integrity, advertisement signature verification, and registry query filtering.

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test
```

## The Search Example

The repo includes an end-to-end proof of concept that demonstrates the full protocol flow. It is the simplest meaningful transaction that proves the trust model works: a web search with zero personal disclosure.

1. Principal generates an Ed25519 keypair and DID document
2. Principal issues a root mandate to the orchestrator (scope: `schema:SearchAction`)
3. Orchestrator queries the local marketplace registry for a search agent
4. Orchestrator mints a capability token bound to the search agent's DID
5. Orchestrator delegates a task mandate to an initiating agent
6. Initiating agent presents the capability token to the search agent
7. Search agent verifies the token — target DID, nonce, signature chain
8. Both agents exchange ephemeral session DIDs
9. Initiating agent discloses nothing — search requires no personal context
10. Search agent executes and returns structured Schema.org results
11. Both agents co-sign a transaction receipt
12. Session closes — ephemeral keys discarded, nonce consumed

```bash
cargo run --bin search
```

The receipt is auditable by both principals. No platform stored anything. No profile was built. No session token persists. The initiating principal disclosed exactly zero personal properties to complete the transaction.

That is the point.

## Protocol Extensions

These are part of the PAP design but not required for a minimal compliant implementation. Each is evaluated against a single test: does this reduce or expand the attack surface for incumbent platform capture?

**Privacy-preserving payment.** PAP rejects data-as-payment. Services need a revenue model. The answer is payment that is unlinkable from identity — Chaumian ecash blind-signed tokens or Lightning Network preimage proofs. The vendor receives proof of value transfer. Nothing identifies the payer. Mandates carry an optional `payment_proof` field. Explicitly excluded: fiat-linked payment rails identifiable by the payment processor.

**Continuity tokens.** The session model specifies that the receiving agent retains nothing after close. This creates a real problem for long-term relationships — returns, support, subscriptions. The continuity token solves it without storing anything on the vendor side. At session close, the vendor writes an encrypted state document and hands it to the orchestrator. The orchestrator stores it locally. The principal controls the TTL. Delete the token to sever the relationship.

**Auto-approval tiers.** Requiring principal review of every micro-transaction produces review fatigue and blind approvals. Auto-approval policies are defined at setup time by the principal — not requested at runtime by agents. A policy cannot be more permissive than the underlying mandate. Default: zero additional disclosure required.

**Hardware-constrained principals.** Confidential computing enclaves (Nitro, SEV, TDX) as a declared fallback for principals without sufficient local hardware for inference. The spec is honest about the trust assumption: this is *virtual local*, not equivalent to local. The enclave provider must not be the same entity as any marketplace agent the orchestrator will transact with.

## The Capture Test

PAP is designed against a specific threat: incumbent platform capture. Every major internet protocol that started with user sovereignty has been captured by the entities with the largest infrastructure footprint. This is not a conspiracy. It is the predictable outcome of letting the entities with the most to lose from a protocol define its implementation.

XMPP was open and federated until the major messaging platforms stopped federating. OAuth was designed for user authorization until it became the mechanism by which platforms accumulated indefinite permission to act on behalf of users. Every open protocol that required an incumbent's infrastructure to function at scale eventually reflected the incumbent's interests.

Any proposal that routes principal context through infrastructure owned by incumbent platforms is out of scope, regardless of the cryptographic framing around it.

Explicit non-goals: compatibility with token economy monetization. Enclave-as-equivalent-to-local. Identity recovery through platform operators. Payment mechanisms linkable to principal identity. Central registries for agent discovery. Mandate structures allowing runtime scope expansion. UI standards permitting arbitrary code execution in the orchestrator context. Any extension that trades trust guarantees for adoption ease.

Good feedback makes the protocol harder to capture. Proposals that introduce new trusted third parties, centralize discovery, soften disclosure enforcement, or create compatibility with metering models should be evaluated as potential capture vectors first and protocol improvements second.

## What Happens Next

PAP v0.1 is a working architecture specification backed by a working Rust implementation. The protocol flow runs end-to-end. The cryptographic guarantees hold. The search example demonstrates zero-disclosure transactions against a local marketplace registry.

What it does not yet have: a network transport layer, federation protocol for marketplace discovery, a WebAuthn integration for production key ceremonies, or a formal RFC submission. Those come next.

The repo is at [github.com/Baur-Software/pap](https://github.com/Baur-Software/pap). Clone it. Run the tests. Run the example. Read the code. The protocol is in the types, the constraints are in the compiler, and the trust model is in the signatures.

If you build agents, the question is not whether your agents can talk to each other. The question is who they answer to.

---

*Todd Baur is the founder of [Baur Software](https://baursoftware.com). PAP v0.1 is published under MIT/Apache-2.0. Comments, objections, and alternative proposals are the point of publishing at draft stage.*

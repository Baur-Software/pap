# Why PAP Exists

**Companion document to the [PAP v0.1 Specification](specification.md)**

This document explains the design motivations behind the Principal Agent Protocol. It is intended for developers, protocol designers, and security engineers evaluating PAP against alternative approaches. It does not repeat the specification — it explains why the specification makes the choices it does.

---

## The Problem in One Sentence

No existing agent protocol enforces context minimization at the protocol level.

Every framework — A2A, MCP, ACP, CrewAI, LangGraph, OpenAI Agents SDK, OpenClaw — treats disclosure as an implementation detail. The model gets a context blob. The developer is responsible for what is in it. The protocol has no opinion.

This was acceptable when agents were single-user assistants running tools on one machine. It is not acceptable when agents transact across trust boundaries on behalf of different principals.

---

## What Changes When Agents Cross Trust Boundaries

A personal assistant talking to its own tools is a trusted system. The user trusts the assistant. The assistant trusts the tools. The tools trust the platform. Everyone shares an operator.

The moment an agent negotiates with another agent controlled by a different operator, every assumption breaks:

1. **The agents do not trust each other.** Neither controls the other's code, training, or objectives.
2. **The operators do not trust each other.** Each has their own business incentives.
3. **The principals may be adversarial.** A buyer's agent and a seller's agent have competing interests.
4. **Context is a liability.** Every field disclosed to an untrusted agent is a field that can be exfiltrated, correlated, or sold.
5. **There is no shared operator to appeal to.** No platform owns both sides of the transaction.

This is the environment PAP is designed for. Not "how does my assistant use tools?" but "how do autonomous agents transact safely when nobody trusts anyone?"

---

## Why Existing Protocols Are Insufficient

### Google A2A

A2A defines agent cards and task lifecycle. It is well-designed for enterprise service orchestration. However:

- Privacy is an "opacity principle" — aspirational guidance, not protocol enforcement
- No selective disclosure mechanism. Agents see full task context or nothing.
- Auth formalization is on the roadmap, not in the spec
- The trust model assumes an enterprise boundary. Cross-organization trust is undefined.

### Anthropic MCP

MCP connects models to tools and data sources. It does this well. However:

- MCP is not an agent-to-agent protocol. It handles tool invocation, not multi-party negotiation.
- There is no concept of agents representing different principals
- The spec explicitly states its security principles are aspirational, not enforced
- No selective disclosure. No session ephemerality. No receipt mechanism.

### Microsoft AutoGen / Semantic Kernel

- Assumes all agents in the system trust each other
- Identity is Azure AD — the trust boundary is the Microsoft ecosystem
- No mechanism for agents outside the ecosystem to participate

### ACP (Agent Communication Protocol)

- REST-based agent interoperability with a thin trust layer
- No cryptographic identity
- Governance merging with A2A (enterprise-first trajectory)

### Agent Frameworks (CrewAI, LangGraph, OpenAI Agents SDK, OpenClaw)

- All treat privacy as an implementation detail
- LangGraph's default is a shared scratchpad — every agent sees everything
- OpenClaw's inter-session messaging has no disclosure scoping
- None define session ephemerality as a protocol guarantee
- None have economic primitives (payment, receipts)
- All are designed for a single operator. None federate.

### The Common Thread

Disclosure is always voluntary. Session residue is always undefined. Privacy is always somebody else's problem. The economic model underneath each system is cloud compute metering — compatible with platform capture, because the platform mediates every interaction.

---

## PAP's Design Decisions

Each decision in the specification addresses a specific failure mode in the landscape above.

### Decision 1: The Human Principal Is the Root of Trust

**Why:** Every other protocol roots trust in a platform, enterprise, or operator. This creates a dependency: the principal's authority is delegated *from* the platform, not *to* it. PAP inverts this. The human holds a device-bound keypair (WebAuthn). All authority flows downward from that keypair through signed mandates. No platform can revoke what it did not grant.

**Spec reference:** Section 4 (Identity Layer), Section 5 (Mandate Structure)

### Decision 2: Deny by Default

**Why:** Positive-list security is the only model that scales across trust boundaries. If an agent's mandate does not explicitly permit an action, the action is denied. This is enforced cryptographically — the mandate signature covers the scope — not by policy or configuration. A misconfigured agent cannot accidentally over-disclose because the mandate does not permit it.

**Spec reference:** Section 5.2 (Scope)

### Decision 3: Delegation Cannot Exceed Parent

**Why:** Hierarchical delegation requires provable bounds. A child mandate's scope must be a subset of its parent's scope. A child's TTL cannot exceed its parent's TTL. This is verified by checking the parent hash chain and comparing scope sets — not by trusting the delegating agent to self-limit. Without this constraint, a single compromised agent could escalate privileges through delegation.

**Spec reference:** Section 5.3 (Delegation Rules)

### Decision 4: Ephemeral Session DIDs

**Why:** Persistent identifiers enable correlation. If the same DID is used across sessions, a colluding set of agents can reconstruct a behavioral profile. Ephemeral session DIDs — generated fresh for each handshake, unlinked to the principal's identity, discarded on session close — make cross-session correlation structurally impossible. The agents see a different counterparty every time.

**Spec reference:** Section 4.3 (Session Keypair), Section 6 (Session Lifecycle)

### Decision 5: SD-JWT Selective Disclosure

**Why:** Sending "all or nothing" context across trust boundaries is the root vulnerability. SD-JWT (IETF draft-ietf-oauth-selective-disclosure-jwt-08) enables per-claim disclosure with independent random salts. Undisclosed claims are never transmitted — only hash commitments exist on the wire. This is not a filter that can be bypassed. It is a cryptographic mechanism that makes non-disclosed claims structurally absent from the agent's view.

**Spec reference:** Section 7 (SD-JWT Disclosure Protocol)

### Decision 6: Co-Signed Receipts with Property References Only

**Why:** Mutual accountability requires both parties to attest to what happened. But storing transaction values creates a surveillance record. PAP receipts record property *types* — "name was disclosed," "price was returned" — never property *values*. Both parties sign. Both can audit the record's structure. Neither retains the data.

**Spec reference:** Section 11 (Receipt Format)

### Decision 7: Progressive Decay Instead of Binary Revocation

**Why:** Surprise revocation is disruptive and creates incentives for agents to cache credentials. Progressive decay (Active → Degraded → ReadOnly → Suspended) gives all parties visibility into declining trust. Non-renewal is revocation — a mandate that is not renewed naturally decays. The principal sees the degradation and can act accordingly.

**Spec reference:** Section 5.5 (Decay States)

### Decision 8: Federated Discovery with No Central Registry

**Why:** Centralized registries create platform capture. Whoever controls the registry controls the ecosystem. PAP's marketplace is federated: operators run their own registries, sync through peer-to-peer federation, and verify agent advertisements via DID signatures. No single entity can delist an agent, change terms, or impose telemetry requirements. Discovery is capability-based — "which agents can satisfy my disclosure constraints?" — not keyword-based.

**Spec reference:** Section 9 (Marketplace), Section 10 (Federation Protocol)

### Decision 9: Schema.org as the Only Vocabulary

**Why:** Custom vocabularies create ecosystem lock-in. Schema.org is maintained by a W3C community group with governance independent of any platform vendor. It describes actions, things, and relationships in a way that is already understood by every search engine, every structured data tool, and every knowledge graph. Using it as the sole vocabulary for agent capabilities, execution results, and UI rendering ensures that PAP agents are interoperable without proprietary extensions.

**Spec reference:** Section 16 (IANA and Vocabulary References)

### Decision 10: No Novel Cryptography

**Why:** Novel cryptographic primitives require years of analysis before they can be trusted. PAP uses Ed25519 (RFC 8032) for signatures, SHA-256 for hashing, WebAuthn for device-bound key generation, W3C DIDs for identity, W3C VCs for credential envelopes, and SD-JWT for selective disclosure. Every primitive has independent specification, multiple implementations, and years of deployment history. If PAP has a cryptographic vulnerability, it is a vulnerability in a standard that the entire industry is also exposed to — not a vulnerability in something we invented.

---

## What PAP Does Not Solve

Intellectual honesty requires stating explicit non-goals:

- **Transport security.** PAP assumes HTTPS/TLS. It does not replace it.
- **Key storage.** The principal must secure their private key. PAP does not specify how.
- **Model behavior.** PAP constrains what data reaches the model, not what the model does with it. A model that hallucinates within its permitted scope is outside the protocol's concern.
- **Single-agent cognition.** PAP is a multi-agent coordination protocol. How one agent reasons, remembers, or plans is not specified. (Papillion's episode store addresses this at the application layer, not the protocol layer.)
- **Payment anonymity.** PAP defines extension points for ecash but relies on external payment systems.
- **DID resolution.** PAP uses `did:key` only — self-contained, no resolver required. Supporting other DID methods is a future consideration.

---

## The Capture Test

Every proposal to the PAP specification is evaluated against a single question:

> *Does this reduce or expand the attack surface for incumbent platform capture?*

If a feature requires a platform's infrastructure to function, it fails the test. If a feature creates a dependency on a centralized service, it fails the test. If a feature trades a trust guarantee for adoption convenience, it fails the test.

Policy-based privacy fails at agent scale because policies are enforced by the platform, and the platform's incentives diverge from the principal's interests. Cryptographic enforcement at the protocol level removes the platform from the trust equation entirely.

This is not an academic distinction. It is the difference between "we promise not to read your data" and "we structurally cannot read your data." The first requires trust in an institution. The second requires trust in mathematics.

PAP chooses mathematics.

---

## Further Reading

- [PAP v0.1 Specification](specification.md) — The authoritative protocol document
- [Memex(RL) Architectural Comparison](memex-comparison.md) — How PAP's memory model relates to long-horizon agent research
- [Your Agent Works for a Platform](https://baursoftware.com/your-agent-works-for-a-platform-it-should-work-for-you/) — Introductory blog post with code walkthrough
- [Show Me the Agents](https://baursoftware.com/show-me-the-agents-pap-in-practice/) — Five real-world scenarios with PAP
- [GitHub Repository](https://github.com/Baur-Software/pap) — Clone it. Test it. Verify the claims.

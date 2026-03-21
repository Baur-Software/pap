# Memex(RL) and PAP: Architectural Comparison

**Reference:** [Memex(RL): Long-Horizon LLM Agent Memory Solutions](https://arxiv.org/abs/2603.04257)

Two approaches to the same root problem — LLM agents that need to coordinate across complex tasks without drowning in context. They solve it at different layers and make different trade-offs.

---

## 1. The Problem Memex(RL) Addresses

LLM agents struggle with long-horizon tasks. Context windows are finite, but trajectories keep growing. The paper identifies that current solutions — truncation, running summaries — are "fundamentally lossy because they compress or discard past evidence itself."

Memex proposes separating compact working context from full-fidelity stored interactions in an external database. RL optimizes the policy for what to summarize, archive, index, and retrieve. The agent maintains a small working set while retaining the ability to "dereference" past evidence on demand.

The core claim: this is "substantially less lossy" than truncation.

---

## 2. Where PAP Addresses the Same Problem (Differently)

PAP does not solve context limitations by making context management smarter. It solves them by making context unnecessary through architectural decomposition.

### Context minimization is structural, not probabilistic

Memex asks: *"Given everything that happened, what should I retrieve?"*
PAP asks: *"What is this agent permitted to see at all?"*

The `Scope` primitive enforces deny-by-default semantics. An agent can only perform actions explicitly listed in its mandate. An empty scope permits nothing:

```rust
// pap-core/src/scope.rs:62-65
pub fn deny_all() -> Self {
    Self { actions: vec![] }
}
```

The `DisclosureSet` defines both what CAN and what MUST NOT be shared, with retention constraints:

```rust
// pap-core/src/scope.rs:36-54
pub struct DisclosureEntry {
    pub schema_type: String,
    pub permitted_properties: Vec<String>,   // what can be shared
    pub prohibited_properties: Vec<String>,  // what must not be shared
    pub session_only: bool,                  // valid only during session
    pub no_retention: bool,                  // receiver must not retain
}
```

Context is bounded at the protocol level. There is no retrieval problem because there is no accumulation.

### Selective disclosure prevents over-sharing cryptographically

SD-JWT selective disclosure (`pap-credential/src/sd_jwt.rs`) independently salts each claim. The `disclose()` method produces only the requested claims — the verifying party never receives undisclosed values:

```rust
// pap-credential/src/sd_jwt.rs:91-115
pub fn disclose(&self, keys: &[&str]) -> Result<Vec<Disclosure>, CredentialError> {
    keys.iter()
        .map(|key| {
            let value = self.claims.get(*key) /* ... */ ;
            let salt = self.salts.get(*key) /* ... */ ;
            Ok(Disclosure { salt, key: key.to_string(), value })
        })
        .collect()
}
```

This is not a retrieval optimization. It is a structural guarantee: undisclosed claims are never transmitted. Memex's approach to context management is probabilistic (the RL policy decides what to retrieve); PAP's is deterministic (the mandate defines what's disclosable).

### Each session is self-contained

Sessions follow a strict state machine (`Initiated -> Open -> Executed -> Closed`) and are ephemeral by design:

```rust
// pap-core/src/session.rs:10-21
pub enum SessionState {
    Initiated,  // Token presented, awaiting verification
    Open,       // Handshake complete, session DIDs exchanged
    Executed,   // Transaction executed within session
    Closed,     // Session closed, ephemeral keys discarded
}
```

Capability tokens are single-use with consumed nonce tracking (`pap-core/src/session.rs:127-143`). Session DIDs are ephemeral and unlinked to the principal identity. There is no context that persists from session N to session N+1.

### Delegation cannot expand scope

Child mandates are cryptographically bounded by their parents:

```rust
// pap-core/src/mandate.rs:119-125
if !self.scope.contains(&scope) {
    return Err(PapError::DelegationExceedsScope);
}
if ttl > self.ttl {
    return Err(PapError::DelegationExceedsTtl);
}
```

This means context narrows as delegation deepens. The opposite of Memex's problem — where context grows as the trajectory lengthens.

### Scalability through federation, not indexing

Memex scales by building a better index over a growing memory store. PAP scales by distributing work across agents that each maintain minimal state.

The `FederatedRegistry` (`pap-federation/src/registry.rs`) coordinates agent discovery across peers with no central state. Marketplace filtering (`pap-marketplace/src/registry.rs`) excludes agents whose disclosure requirements exceed the mandate's permissions *before* any handshake begins.

### Audit without context bloat

Transaction receipts (`pap-core/src/receipt.rs:8-33`) contain property references only — never values. They record `["schema:Person.schema:name"]`, not `["Alice"]`. Co-signed by both session parties with ephemeral keys, they provide cryptographic proof of what categories of information were exchanged without storing or transmitting the information itself.

---

## 3. Where PAP Does NOT Solve This (And Why)

PAP makes deliberate trade-offs that leave certain Memex use cases unaddressed.

### No temporal reasoning across sessions

PAP sessions are isolated and ephemeral. There is no mechanism for an agent to reason about the sequence or causality of past interactions. Memex's "dereferencing past evidence" — looking back at step 47 of a 1000-step trajectory — has no PAP analog.

**Why PAP doesn't solve this:** Temporal linking between sessions creates correlation vectors. If session N and session N+1 can be linked, an observer can reconstruct interaction patterns. PAP's session unlinkability is a privacy guarantee, not an oversight. Ephemeral session DIDs and key zeroization on close (`pap-did/src/session.rs`) are the mechanism.

### No single-agent long-horizon learning

PAP assumes task decomposition into independent transactions. If a task genuinely requires one agent reasoning across 1000 sequential steps — maze solving, long-form writing, iterative scientific discovery — PAP does not help. The protocol has no mechanism for an agent to carry knowledge forward.

**Why PAP doesn't solve this:** PAP's threat model is agent capture. An agent that accumulates context over time becomes a target — compromising it yields the full interaction history. Stateless agents have nothing to steal. The README states the design principle explicitly: "The cloud is a stateless utility invoked by agents, not a relationship that accumulates principal context."

### No cross-session knowledge accumulation

Agents cannot learn from past interactions by design. The only cross-session state mechanism is `ContinuityToken` (`pap-core/src/extensions.rs:20-56`) — encrypted vendor state blobs with principal-controlled TTL. These enable vendor relationship continuity (e.g., "remember my seat preference"), not agent learning.

**Why PAP doesn't solve this:** Memex's RL-optimized memory policies train the agent to decide what to remember. PAP's position is that the principal — not the agent — should control what persists. The `ContinuityToken` model makes this explicit: the vendor writes encrypted state, but the principal holds it, controls its TTL, and can delete it unilaterally.

### Fixed scope — no runtime expansion

If a PAP agent discovers mid-task that it needs additional context, it cannot get it. `DelegationExceedsScope` is enforced cryptographically at mandate issuance. Memex handles this naturally through dynamic retrieval from its indexed store.

**Why PAP doesn't solve this:** Runtime scope expansion is an explicit non-goal (specification.md section 3.4). It is the vector for platform capture — an agent that can request more permissions at runtime can gradually expand its authority. PAP mandates are fixed at issuance. If more scope is needed, the principal issues a new mandate.

---

## 4. Different Layers, Different Trade-offs

|  | Memex(RL) | PAP |
|---|---|---|
| **Layer** | Single-agent cognition | Multi-agent coordination |
| **Problem** | "How does one agent remember?" | "How do agents trust each other?" |
| **Scaling axis** | Vertical (bigger memory per agent) | Horizontal (more agents, less per agent) |
| **Context strategy** | Retrieve the right context | Prevent the wrong context |
| **State model** | Persistent, indexed | Ephemeral, discarded |
| **Privacy model** | Not addressed | Core design constraint |
| **Failure mode** | Retrieves wrong context | Over-scoped mandate |

These are complementary, not competing. A PAP agent could use Memex internally for long-horizon reasoning within its scoped task, while PAP governs the trust boundaries between agents.

The architectural question is whether the problem admits decomposition. If it does, PAP's horizontal model avoids the memory problem entirely — there is no long trajectory to index because each agent's trajectory is short and self-contained. If it does not, Memex-style vertical scaling is necessary for the inherently sequential portions.

Most real systems will need both.

---

## 5. When Each Approach Applies

**Memex-style approaches are necessary when:**
- The task is inherently sequential and non-decomposable (iterative refinement, long-form generation, trajectory optimization)
- A single agent needs to learn from its own trajectory
- Historical context genuinely improves future decisions within the same task

**PAP applies when:**
- The task decomposes into independent sub-tasks with clear trust boundaries
- Privacy and disclosure minimization matter
- Deterministic protocols are required over probabilistic retrieval
- Scalability is horizontal (more agents) not vertical (smarter agent)

**Both are needed when:**
- Individual agents within a PAP federation need long-horizon memory for their scoped tasks
- The orchestrator needs to improve agent selection based on past outcomes
- Trust boundaries and disclosure rules must hold between agents, even as individual agents grow more capable internally

---

## Code References

| File | Relevance |
|------|-----------|
| `pap-core/src/scope.rs` | Deny-by-default scope model, disclosure sets, property refs |
| `pap-core/src/mandate.rs` | Delegation containment, decay states, cryptographic binding |
| `pap-core/src/session.rs` | Ephemeral session lifecycle, single-use nonces, state machine |
| `pap-core/src/receipt.rs` | Co-signed receipts with property references only |
| `pap-core/src/extensions.rs` | Continuity tokens (principal-controlled cross-session state) |
| `pap-credential/src/sd_jwt.rs` | Selective disclosure JWT — per-claim salting and disclosure |
| `pap-federation/src/registry.rs` | Federated discovery with no central state |
| `pap-marketplace/src/registry.rs` | Pre-handshake filtering by disclosure requirements |

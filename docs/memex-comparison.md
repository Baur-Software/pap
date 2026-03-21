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

## 6. Bringing Them Together: The Orchestrator as Memory Layer

PAP specifies the handshake, mandates, scopes, receipts, and federation. It does not prescribe what the orchestrator does with the information it already has. The trust hierarchy (specification section 3.1) places the orchestrator inside the principal's trust boundary with "full principal context" by design. What it does with that context is an implementation choice, not a protocol concern.

This is where Memex and PAP meet: the orchestrator remembers, the protocol forgets.

### The orchestrator is left to the implementor

Any PAP-compliant orchestrator can add memory without changing the protocol. A minimal orchestrator could forget everything after each session. Papillion — the reference implementation — chooses to remember every mandated interaction on-device, giving users a full picture of their agent relationships.

Papillion already holds past interactions in `AppState.completed_runs` (`apps/papillion/src/state.rs:37`). The question is making this structured, persistent, and useful rather than a flat in-memory log that disappears on restart.

### Why persistence matters for adoption

People will not adopt a protocol they cannot see working. If every interaction is ephemeral and forgotten, the user has no relationship with the system. A persistent memory layer enables:

- "Show me every agent I've authorized" — visible mandate history
- "Which search agent worked best last month?" — outcome-based agent selection
- "I never want to disclose my email again" — disclosure patterns inform future scopes
- "What did that agent do with my data?" — receipt-anchored audit trail

The orchestrator remembers so the protocol can forget. Agents stay stateless. Sessions stay ephemeral. But the user sees their full history.

### The persistence gap

Papillion today is entirely in-memory. `AppState` holds everything in `RwLock<>` — completed runs, principal keypairs, federation caches, bookmarks. All lost on restart. There is no SQLite, no file-based storage, no database backend. The `tauri-plugin-store` dependency exists in `Cargo.toml` but is unused.

The memory layer requires actual persistence: episodes anchored to receipts, agent profiles aggregated from outcomes, principal keypairs auto-saved, retention policies stored durably.

### SQLite + JSON-LD: The natural memory substrate

Every delegated agent in PAP returns JSON-LD — Schema.org typed structured data. This is where Memex's "dereference past evidence" maps cleanly onto PAP:

- **The evidence is JSON-LD.** Every agent result is already structured with `@type`, `@context`, and typed properties.
- **The index is SQLite.** `json_extract()` queries directly into JSON-LD payloads without an ORM. `json_extract(result, '$.@type')` finds every `schema:SearchResult` across all episodes.
- **The relationships are Schema.org types.** Contextual patterns emerge from the data: "every time I searched for flights, I then booked a hotel" is a temporal query over typed episodes. `schema:SearchAction` followed by `schema:ReserveAction` with overlapping disclosure refs — the ontology provides the linkage for free.
- **FTS5 full-text search** over JSON-LD descriptions enables Memex-style semantic retrieval without embeddings.
- **Single-file database** in `app_data_dir()` — portable, backupable, principal-owned.

The structured data that PAP mandates for interoperability becomes the memory substrate at no additional cost. Schema.org types that exist for agent communication double as the indexing ontology for experience memory.

Encrypted at rest with a key derived from the principal's Ed25519 seed. If the seed is lost, the memory is unrecoverable — the principal controls access to their own history.

### The flow: remember before, forget after

```
User Intent
  → Consult past episodes for this action type (what worked?)
  → Rank agents by outcome history, suggest minimal scope
  → Discover agents from federation (existing, unchanged)
  → Issue mandate with informed scope/TTL (existing mechanism)
  → Execute 6-phase handshake (UNCHANGED — protocol layer untouched)
  → Record episode: receipt + JSON-LD result → SQLite
  → Update agent profile with new outcome
  → Apply retention policy (keep / compress / forget)
```

Memory operates before phase 1 (informing decisions) and after phase 6 (recording outcomes). The 6-phase handshake is untouched. No protocol messages change. No new information flows to downstream agents.

### What's protocol vs. what's Papillion

**PAP protocol (unchanged):**
- 6-phase handshake, mandate issuance, scope containment, session lifecycle
- SD-JWT selective disclosure, receipt structure (refs only), federation sync
- Downstream agents remain stateless — they have no idea the orchestrator remembers

**Papillion app (implementation choice):**
- `completed_runs` becomes a persistent SQLite episode store
- Agent selection goes from first-match to outcome-ranked
- Scope configuration goes from hardcoded to informed-by-experience
- TTL calibrated per-agent from observed execution durations

### Mandate decay informed by memory

Memory informs two renewal decisions without changing the decay mechanism:

1. **TTL calibration**: Agent profiles track actual execution durations. A 2-second search agent does not need a 1-hour mandate — a 10-minute TTL with proactive renewal is tighter security.
2. **Renewal worthiness**: Before renewing a Degraded mandate back to Active, memory answers: "Is this agent worth renewing?" Declining quality scores or increasing failure rates suggest letting the mandate decay.

The `compute_decay_state` method still calculates state from TTL. The `transition_decay` method still validates transitions. Memory informs whether the orchestrator chooses to renew — it does not bypass the mechanism.

### Guarantees

**All PAP protocol guarantees preserved.** Memory never crosses the trust boundary. Downstream agents cannot tell the difference between an orchestrator with memory and one without.

**Added by Papillion's memory layer:**
- Memory is principal-controlled — the user can view, export, and delete their history
- Memory is on-device only — never serialized to protocol messages, never transmitted
- Memory degradation is safe — bad or missing memory leads to suboptimal agent selection, not data leakage
- Forget is real — deleted episodes are destroyed, not archived or soft-deleted

### Failure modes

| Failure | Impact | Mitigation |
|---------|--------|------------|
| Database loss | Falls back to first-match agent selection | Memory is advisory, not authoritative |
| Stale agent profiles | Agent quality may have changed | Recency weighting + 5-minute federation refresh |
| Device compromise | Stored episodes readable | At-rest encryption with principal seed. Same threat model as today. |

### Where Memex-style RL could fit (future work)

All optimization targets orchestrator policy, never agent behavior:

- **What to remember**: Did a retained episode improve a subsequent decision?
- **Which agent to pick**: Outcome quality vs. historical average for that action type
- **How tight the scope**: Successful handshake with tighter scope = better

This is future work. The immediate value is simpler: Papillion persists mandated interactions in an encrypted, queryable, JSON-LD-indexed store so users can see their agent relationships working.

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
| `apps/papillion/src/state.rs` | AppState with in-memory `completed_runs` (persistence gap) |
| `apps/papillion/src/commands/orchestrator.rs` | Scenario execution, agent selection, mandate issuance |

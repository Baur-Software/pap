# Dynamic Agents — Design Spec

**Date:** 2026-04-01
**Status:** Approved
**Version target:** post-0.5.9

---

## 1. Problem

The current agent library is 13 compiled Rust structs. Adding a new agent requires writing
Rust, rebuilding the binary, and shipping a release. This limits the ecosystem to what the
core team has time to implement and makes the protocol feel small. The goal is to let agents
be defined from structured config — enabling a pre-built catalog of hundreds of agents and
letting users create new agents from a natural language prompt — while keeping the full
PAP trust model intact.

---

## 2. Scope

This spec covers:

- The `DynamicAgentDef` data model
- `DynamicAgentHandler` — hybrid HTTP + LLM execution within the 6-phase protocol
- The agents catalog (~300 pre-built entries in TOML)
- Persistence (new `agents` table in Papillon profile DB)
- Registration integration with the existing `AgentSet` pipeline
- New Tauri commands for agent management
- Federation behavior (what federates, what stays local)

Out of scope:

- Dynamic agent composition / sub-orchestration (dynamic agents are leaf nodes only — see §5)
- Arbitrary code execution in agent context
- Server-side agent generation on Chrysalis (removed on privacy grounds — see §8)

---

## 3. Data Model

### 3.1. DynamicAgentDef

```rust
pub struct DynamicAgentDef {
    // Identity — DID derived from operator_key_seed is the canonical identifier.
    // No UUID; the DID is the primary key in both DB and federation.
    pub agent_did: Option<String>,           // None until first registration

    // Metadata (populates AgentAdvertisement)
    pub schema_version: u32,                 // currently 1
    pub name: String,
    pub provider: String,
    pub description: String,                 // natural language; never leaves device
    pub action: String,                      // "schema:SearchAction"
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,

    // Execution config
    pub endpoint: Option<HttpEndpointConfig>,
    pub llm_instructions: String,            // sandboxed fallback prompt; never leaves device

    // Sub-agent metadata (declarative only — see §5)
    pub subagents: Vec<String>,              // schema.org action types this agent works with.
                                             // Read by orchestrator to pre-provision mandates.
                                             // Never used to issue mandates from this agent.

    // Source tracking
    pub source: DynamicAgentSource,          // Catalog | UserCreated | Generated

    // Operator keypair — see §3.3 for key separation rules
    pub operator_key_seed: Option<[u8; 32]>, // None until first registration;
                                             // 32-byte Ed25519 seed for advertisement signing only

    // Publication state
    pub published_to: Vec<String>,           // registry URLs advertisement was POSTed to

    pub created_at: String,                  // RFC 3339
    pub updated_at: String,
}

pub enum DynamicAgentSource {
    Catalog,       // loaded from crates/pap-agents/catalog/ at first startup
    UserCreated,   // created interactively by the principal
    Generated,     // created by LLM from a prompt
}
```

### 3.2. HttpEndpointConfig

```rust
pub struct HttpEndpointConfig {
    pub url_template: String,           // "https://api.example.com/v1?q={query}"
                                        // {query} is the only substitution variable
    pub method: HttpMethod,             // Get | Post only
    pub headers: HashMap<String, String>, // API keys — see §3.4 for isolation rules
    pub body_template: Option<String>,  // None for Get/Head; enforced at save time
    pub response_jsonpath: String,      // RFC 9535 JSONPath dialect
    pub response_schema_type: String,   // "schema:SearchResultsPage"
}

pub enum HttpMethod { Get, Post }
```

### 3.3. Key Separation

Two distinct keypairs exist per dynamic agent. They MUST NOT be conflated:

| Keypair | Seed | Purpose | Persisted? |
|---------|------|---------|-----------|
| Operator keypair | `operator_key_seed` in DB | Signs `AgentAdvertisement` | Yes — in `agents` table |
| Session keypair | Generated fresh per session | Envelope signing, DID exchange (§6.3) | No — discarded at session close per spec §4.4 |

`DynamicAgentHandler::handle_token()` generates a new session keypair on every invocation.
It MUST NOT derive session keys from `operator_key_seed`.

### 3.4. HttpEndpointConfig Isolation

`HttpEndpointConfig` (including `headers`) MUST NOT appear in:

- Any Tauri IPC response to the frontend (strip before serialization at the command boundary)
- Any `AgentAdvertisement` sent to federation peers
- Any `TransactionReceipt` field
- Any log output

`headers` is encrypted at rest using the principal's device-bound key (same key material used
for profile encryption). Decryption happens only inside `DynamicAgentHandler::execute()`,
never outside the Rust handler boundary.

---

## 4. Execution Model

`DynamicAgentHandler` implements `AgentHandler` directly (not via `AgentExecutor + SimpleAgent`).
Phases 1–3 and 5–6 are identical to `SimpleAgent`. Phase 4 is hybrid:

```
Phase 4 — execute(query: &str) -> Result<serde_json::Value, TransportError>

Step 1: HTTP attempt (if endpoint present)
  - Validate URL at call time (https:// only, no RFC 1918, no localhost)
  - Substitute {query} into url_template and body_template
  - Execute HTTP call with timeout (5s default)
  - On 2xx: extract via response_jsonpath (RFC 9535)
    - Zero matches → fall through to Step 2
    - One or more matches → build Schema.org envelope, go to Step 3
  - On error / timeout → fall through to Step 2

Step 2: LLM fallback
  - Build isolated prompt:
      system = llm_instructions  (no principal context, no session disclosures)
      user   = query             (the bare query string only)
  - Route through OrchestratorConfig.llm_provider
    (BuiltIn → ModelManager, Ollama/Mistral/OpenAI → llm.rs chat())
  - Receive raw text response
  - Wrap in Schema.org Answer envelope

Step 3: Schema validation
  - Validate ExecutionResult against Schema.org JSON-LD structure
  - Strip any field that is not a Schema.org property type reference
  - Raw LLM output MUST NOT pass through verbatim
  - On validation failure → return TransportError::InvalidResult

Receipt fields:
  - `executed` = def.action  (e.g., "schema:SearchAction")
  - `returned`  = def.returns.first() (e.g., "schema:SearchResult")
  - Never populated from HTTP response body or LLM output (spec §11.5)
```

### 4.1. URL Safety

Enforced at `save_agent` time AND at execution time (defense in depth):

- Scheme MUST be `https://`
- Host MUST NOT be `localhost`, `127.*`, `10.*`, `172.16–31.*`, `192.168.*`, `169.254.*`
- Host MUST NOT be an IPv4 or IPv6 address literal
- `body_template` MUST be `None` for `HttpMethod::Get`

Violations at execution time return `TransportError::SsrfBlocked` without executing.

### 4.2. LLM Sandbox Invariants

The LLM call in Step 2 MUST:
- Receive only `llm_instructions` (system) and `query` (user)
- Have no access to session disclosures, principal context, or mandate fields
- Produce only the text content of the response; no structured protocol output
- Run with a token cap (300 tokens for `BuiltIn` provider; external providers use their
  own configured limits — no override imposed)

---

## 5. Sub-Agent Metadata (Declarative Only)

`DynamicAgentDef.subagents` lists Schema.org action types the agent is designed to work
alongside. This field is purely declarative metadata — it is read by the orchestrator
before issuing the capability token, allowing it to pre-provision sub-mandates for the
agent's declared action types.

**A `DynamicAgentHandler` MUST NOT:**
- Issue child mandates
- Issue capability tokens
- Initiate 6-phase sessions with other agents
- Act as an orchestrator in any capacity

Dynamic agents are leaf nodes in the mandate chain. The orchestrator is the only mandate
issuer. This is not a limitation of the implementation — it is a protocol invariant (spec
§5.5 R4–R5, §3.1).

`subagents` entries that are not contained within the principal's grant to the orchestrator
are ignored. The orchestrator validates containment before pre-provisioning (spec §5.4.5).

---

## 6. Catalog

### 6.1. Structure

```
crates/pap-agents/catalog/
  search/       # web search, academic, code, news
  knowledge/    # encyclopedias, dictionaries, fact databases
  science/      # astronomy, biology, earth, climate, chemistry
  health/       # drugs, nutrition, medical literature
  finance/      # exchange rates, stocks, crypto, economics
  geo/          # geocoding, transit, maps, elevation
  culture/      # museums, music, books, film, games
  food/         # recipes, ingredients, nutrition
  sports/       # scores, stats, schedules
  government/   # legislation, regulations, open data
  composed/     # multi-action workflow hints (subagents populated, no endpoint)
```

Target: ~300 entries. Catalog TOML files contain all `DynamicAgentDef` fields except
`operator_key_seed`, `agent_did`, `published_to`, `created_at`, `updated_at` — those are
generated at first load.

### 6.2. Example Catalog Entry

```toml
schema_version = 1
name = "Open Food Facts"
provider = "Open Food Facts"
description = "Look up nutritional data for food products by name or barcode"
action = "schema:SearchAction"
object_types = ["schema:FoodEstablishment"]
requires_disclosure = []
returns = ["schema:NutritionInformation"]
source = "Catalog"
llm_instructions = """
You are a nutrition lookup assistant. The user has asked about a food product.
Return the nutritional information as accurately as possible.
Limit your response to factual nutritional data only.
"""
subagents = []

[endpoint]
url_template = "https://world.openfoodfacts.org/cgi/search.pl?search_terms={query}&search_simple=1&action=process&json=1"
method = "Get"
response_jsonpath = "$.products[0]"
response_schema_type = "schema:NutritionInformation"
```

### 6.3. Catalog Integrity

Catalog TOML files are part of the repository and subject to the same code review process
as Rust source. All catalog entries MUST:

- Use `https://` endpoints only
- Pass URL safety validation
- Reference a real, documented public API
- Include meaningful `llm_instructions` for fallback quality

### 6.4. First-Startup Loading

On first startup, Papillon reads all TOML files from the catalog directory, generates
`operator_key_seed` + `agent_did` for each, inserts into the `agents` table with
`source = "Catalog"`, and registers via `register_dynamic()`. Subsequent startups load
from DB. New catalog entries added in a release are detected by catalog path — a stable
`catalog_path` column (e.g., `"search/duckduckgo.toml"`) uniquely identifies each entry
across installs and upgrades. If a catalog path has no matching row in `agents`, it is a
new entry and gets inserted. Removed catalog entries remain in DB (user may have published
them to federation) but are flagged `removed_from_catalog = true` and excluded from
default listings.

The `catalog_path` column is added to the `agents` table:

```sql
ALTER TABLE agents ADD COLUMN catalog_path TEXT;  -- NULL for user_created / generated
CREATE UNIQUE INDEX idx_agents_catalog_path ON agents(catalog_path)
    WHERE catalog_path IS NOT NULL;
```

---

## 7. Persistence

### 7.1. New `agents` Table (Papillon Profile DB)

Migration: `0002_agents.sql`

```sql
CREATE TABLE agents (
    agent_did TEXT PRIMARY KEY,              -- did:key:z..., canonical identity
    schema_version INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    description TEXT NOT NULL,
    action TEXT NOT NULL,
    object_types_json TEXT NOT NULL DEFAULT '[]',
    requires_disclosure_json TEXT NOT NULL DEFAULT '[]',
    returns_json TEXT NOT NULL DEFAULT '[]',
    endpoint_json TEXT,                      -- NULL = LLM-only; encrypted at rest
    llm_instructions TEXT NOT NULL DEFAULT '',
    subagents_json TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL CHECK(source IN ('catalog','user_created','generated')),
    operator_key_seed BLOB NOT NULL,         -- 32 bytes; always present after first registration
    published_to_json TEXT NOT NULL DEFAULT '[]',
    removed_from_catalog INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_agents_action ON agents(action);
CREATE INDEX idx_agents_source ON agents(source);
```

### 7.2. Relationship to Existing Tables

- `agent_profiles (agent_did_hash, success_rate, avg_quality, ...)` — tracks performance
  metrics. `agent_did_hash` links to this table's `agent_did`. No changes to `agent_profiles`.
- `episodes` — unchanged. Episodes reference `agent_did_hash` and `agent_name`, both
  available from this table.

### 7.3. Chrysalis — No New Tables

Dynamic agent advertisements are `AgentAdvertisement` JSON stored in the existing `agents`
table via the existing `POST /api/agents` endpoint. The registry does not know or care
whether an advertisement came from a compiled or dynamic agent.

---

## 8. Generation Pipeline

Agent generation is client-side only. The Chrysalis `POST /api/agents/generate` endpoint
proposed in earlier design iterations is removed. Sending the user's agent-creation prompt
to a server discloses principal intent — a T1 context profiling risk (spec §3.3).

```
User types: "I need an agent that finds recipe nutrition info"
  ↓
Papillon sends structured generation prompt to OrchestratorConfig.llm_provider:
  system: "Produce a DynamicAgentDef JSON object. Use Schema.org action types.
           Prefer zero-auth public HTTPS APIs. Include llm_instructions as fallback.
           Output only valid JSON matching the DynamicAgentDef schema."
  user:   <user's prompt>
  ↓
LLM returns DynamicAgentDef JSON
  ↓
Validate:
  - schema_version present
  - action is a known schema.org type
  - url_template passes URL safety checks (if present)
  - response_jsonpath is valid RFC 9535 syntax (if present)
  - required fields non-empty
  ↓
If invalid → retry once with validation errors appended; if still invalid → surface error
  ↓
[ATOMIC] Generate operator_key_seed → derive agent_did →
         build + sign AgentAdvertisement →
         INSERT into agents table
  ↓
register_dynamic(def, llm_provider) on live AgentSet → queryable immediately
  ↓
UI shows new agent; "Publish to federation" is a separate explicit action
```

The keypair generation, advertisement signing, and DB insert are atomic. No unsigned
intermediate state exists.

---

## 9. Registration

### 9.1. AgentSet Extension

```rust
impl AgentSet {
    pub fn register_dynamic(
        &mut self,
        def: &DynamicAgentDef,
        llm_provider: Arc<LlmProvider>,
    ) -> Result<String, RegistrationError>  // returns agent_did
}
```

Internal steps:
1. Restore Ed25519 keypair from `def.operator_key_seed` (always present at call time)
2. Build `AgentAdvertisement` from def fields (no `AgentMeta` involved)
3. Sign advertisement with operator keypair
4. Verify advertisement is signed before accepting (spec §9.4)
5. `registry.register_local(advertisement)`
6. Insert keypair into `self.keypairs`
7. Insert `Arc<DynamicAgentHandler>` into `self.handlers`
8. Return `agent_did`

`build_agents()` is unchanged. Dynamic registration is a post-build step.

### 9.2. Startup Sequence

```rust
// 1. Compiled agents (unchanged)
let mut agent_set = build_agents(extra);

// 2. DB agents
let defs = db.load_all_agents().await?;
for def in defs {
    agent_set.register_dynamic(&def, llm_provider.clone())?;
}

// 3. Existing local_registry, now includes dynamic agents
let local_registry = Arc::new(Mutex::new(agent_set.registry));
```

### 9.3. Runtime Registration

Creating a new agent mid-session:

```rust
db.insert_agent(&def).await?;                            // atomic: seed + sign + insert
agent_set.lock().register_dynamic(&def, llm_provider)?;  // live immediately
```

No restart required.

---

## 10. Federation

What federates vs what stays local:

| Data | Federates? | Notes |
|------|-----------|-------|
| `AgentAdvertisement` (name, DID, capabilities, signature) | Yes | Identical to compiled agent ads |
| `DynamicAgentDef` (full struct) | Never | Personal config, stays on device |
| `operator_key_seed` | Never | Private key material |
| `HttpEndpointConfig` incl. headers | Never | API keys are personal |
| `llm_instructions` | Never | Personal config |
| `description` | Never | May contain sensitive intent |

### 10.1. Advertisement Rate Limiting

Federation peers MUST enforce a per-principal-DID advertisement limit. This is elevated
from a SHOULD (spec §15.5) to a MUST for this implementation. Chrysalis default: 100
advertisements per principal DID. Configurable in `registry.toml`:

```toml
[federation]
max_ads_per_principal = 100
```

Bulk publication via the `publish_agent` command requires per-advertisement principal
confirmation. No batch-publish API is exposed.

---

## 11. New Tauri Commands

New file: `apps/papillon/src/commands/agents.rs`

```
generate_agent(prompt: String) -> DynamicAgentDef
  // Client-side LLM generation. Returns preview — not yet saved.
  // HttpEndpointConfig.headers stripped before returning to frontend.

save_agent(def: DynamicAgentDef) -> AgentInfo
  // Atomically: generate keypair → sign → insert DB → register live.
  // Returns AgentInfo (no sensitive fields).

list_agents() -> Vec<AgentInfo>
  // All agents: compiled + catalog + user_created + generated.
  // Source field distinguishes them. No sensitive fields.

delete_agent(did: String) -> ()
  // DB agents only. Compiled agents cannot be deleted.
  // Does not auto-unpublish from federation (use unpublish_agent first).

publish_agent(did: String, registry_url: String) -> ()
  // POSTs AgentAdvertisement only to registry.
  // Updates published_to in DB.

unpublish_agent(did: String, registry_url: String) -> ()
  // DELETEs advertisement from registry by hash.
  // Updates published_to in DB.

update_agent(def: DynamicAgentDef) -> AgentInfo
  // Re-signs advertisement if capability fields changed.
  // Re-publishes to all URLs in published_to if already published.
  // operator_key_seed is NOT regenerated on update (DID stability).
```

`AgentInfo` (the safe frontend-facing type) contains: `name`, `provider_name`,
`provider_did`, `capabilities`, `object_types`, `requires_disclosure`, `returns`,
`source`, `agent_did`, `published_to`. No `operator_key_seed`, no `HttpEndpointConfig`,
no `llm_instructions`, no `description`.

---

## 12. Testing Requirements

Per CLAUDE.md: comprehensive tests required for all features, especially cryptographic
operations and protocol invariants.

### 12.1. Unit Tests (pap-agents)

- `DynamicAgentDef` serialization round-trip (TOML → struct → TOML)
- URL safety validation: https allowed, http rejected, RFC 1918 rejected, localhost rejected
- `body_template` with GET method rejected at save time
- `operator_key_seed` → `agent_did` derivation is deterministic
- `register_dynamic()` produces a valid signed advertisement
- `register_dynamic()` rejects unsigned advertisements
- Session keypair is freshly generated (not derived from operator seed)
- `schema_version` mismatch triggers migration, not silent default

### 12.2. Integration Tests (pap-agents)

- Full startup sequence: catalog TOML → DB insert → `register_dynamic()` → queryable
- Runtime registration: insert → register → immediately queryable
- Re-registration after restart: load from DB → same DID → same advertisement hash
- `DynamicAgentHandler` Phase 4: HTTP success path
- `DynamicAgentHandler` Phase 4: HTTP failure → LLM fallback
- `DynamicAgentHandler` Phase 4: LLM fallback output is schema-validated
- Receipt `executed`/`returned` fields are type references, never LLM content
- `HttpEndpointConfig.headers` absent from all serialized outputs
- SSRF block: RFC 1918 URL rejected at execution time
- Full 6-phase handshake with a dynamic agent via `SimpleSession` test harness
- `DynamicAgentHandler` does not issue child mandates (static assertion + runtime check)

### 12.3. Catalog Tests

- All ~300 TOML files parse without error
- All `url_template` values pass URL safety validation
- All `response_jsonpath` values are valid RFC 9535 syntax
- All `action` values are known schema.org types

---

## 13. Open Questions (Resolved)

| Question | Decision |
|----------|---------|
| Should dynamic agents act as mini-orchestrators? | No. Leaf nodes only. Spec §5.5 R4-R5. |
| Should Chrysalis generate agent defs server-side? | No. T1 context profiling risk. Client-side only. |
| UUID or DID as primary key? | DID. UUID removed. |
| Should catalog agents populate llm_instructions? | Yes — required for fallback quality. |
| Should generation be retried on validation failure? | Once, with error context appended to prompt. |
| What JSONPath dialect? | RFC 9535. |

---

## 14. Files Changed

| File | Change |
|------|--------|
| `crates/pap-agents/src/dynamic.rs` | New — `DynamicAgentDef`, `HttpEndpointConfig`, `DynamicAgentHandler` |
| `crates/pap-agents/src/registry.rs` | Add `AgentSet::register_dynamic()` |
| `crates/pap-agents/src/lib.rs` | Export `dynamic` module |
| `crates/pap-agents/catalog/**/*.toml` | New — ~300 catalog entries |
| `crates/papillon-shared/src/db/native.rs` | Add migration `0002_agents.sql` |
| `crates/papillon-shared/src/types.rs` | Add `AgentInfo` safe frontend type, `DynamicAgentSource` |
| `apps/papillon/src/commands/agents.rs` | New — Tauri commands |
| `apps/papillon/src/commands/mod.rs` | Register agents commands |
| `apps/papillon/src/lib.rs` | Startup: load DB agents → `register_dynamic()` |

# Project: Principal Agent Protocol (PAP)

PAP is **not a SaaS app or demo**—it's a protocol specification with a reference implementation in Rust. We're building a secure, privacy-preserving agent negotiation protocol that places the human principal at the root of trust.

## Papillon — The Agentic Browser

Papillon is the reference client for the pap:// protocol. It is **not a SaaS app or AI chatbot** — it is the browser for the agentic age, the same conceptual leap that Mosaic was for the web. Its job is to let people act with intent online, at a personal level, without ceding control to any platform.

### The Address Bar Is a Multifunction Tool

The address bar (`InlinePrompt` in `pages/canvas.rs`) accepts three input forms:

1. **Natural-language prompts** → routed through `detect_intent()` → 6-phase PAP handshake → rendered canvas block
2. **`pap://` URIs** → resolved by `resolve_pap_uri()` in `papillon-shared` to a local intent, DID endpoint, registry, HTTPS, or WSS target
3. **`pap+https://` and `pap+wss://` URLs** → federated agent endpoints; the papillon-extension handles these in the browser so ordinary links become zero-trust agent interactions automatically

### The Canvas

The canvas (`pages/canvas.rs` + `state/canvas.rs`) is an **agentic compute surface** — a persistent, named collection of blocks. Each block represents one intent → agent → result cycle.

**Block lifecycle** (`BlockState` in `papillon-shared`):

```
Resolving (phases 1–6) → Resolved | Failed | AwaitingApproval | Ghost | Outcome
```

- **Ghost**: Pre-execution "dry run" preview — shows what the agent *will* see (disclosure scope) and *will* return (schema.org types) before any data moves. The user can inspect and approve or reject.
- **AwaitingApproval**: Mandate dry-run plan has been built; skeleton preview (block-filled characters) shows the result shape. User sees `[ APPROVE ] / [ REJECT ]` with exact disclosure and mandate TTL.
- **Resolving**: 6 phase-dots animate through token presentation → mandate → disclosure → execution → co-signed receipt → session close.
- **Resolved**: Content rendered from schema.org vocabulary via the `BlockRenderer` + `RendererRegistry`.
- **Outcome**: Multi-agent synthesis result with expandable `ProvenanceLayer` showing each contributing agent's DID, mandate scope, decay state, and co-signed receipt.

**Block references**: Prompts can embed `{{block:ID}}` to compose results — e.g. "summarize {{block:abc-123}}" passes the prior block's content to the next agent.

**`pap://` links from rendered content** route through `submit_agent_link()` with `LinkOrigin::Agent` — so agent-rendered blocks can link to other agents without escaping into the principal trust domain.

### TTL and Data Freshness

Every mandate is time-bounded (default 1 h in `handshake/mod.rs`, configurable). The TTL means:

- Data on canvas blocks has a natural expiry tied to the mandate that produced it
- Users can **refresh** by re-issuing a prompt, clicking retry on a block, or setting canvas-level TTL preferences
- The orchestrator can hold **pre-approvals** from prior sessions (stored in the long-horizon memex / episode DB) so recurring queries don't require manual gate approval every time
- The `AwaitingApproval` block shows `"MANDATE DURATION ~1h (renewable, bounded)"` so the user always knows the trust boundary

### Schema.org → UI (No UI Over the Wire)

Agents deliver **data**, not markup. The `RendererRegistry` (`block_renderer/registry.rs`) maps `schema:@type` values to typed templates:

- **Shipped templates** cover ~25 types: `FlightReservation`, `WeatherForecast`, `NewsArticle`, `ScholarlyArticle`, `DefinedTerm`, `JobPosting`, `Product`, `Event`, `Person`, `GeoCoordinates`, etc.
- **User-edited templates** are stored in `TemplateLibrary` (`pages/settings/templates_tab/`) — treated as a personal CMS
- **Generic stream renderer** handles all other types automatically via `field_classify.rs` + `schema_property.rs`
- Agents can also register **agent-scoped renderers** keyed by `(agent_did, schema_type)` for fully custom output without affecting the global vocabulary mapping

This is why "a FlightReservation looks like what a human would expect to see" — the vocabulary shape drives the component shape, and Papillon owns that mapping on the client.

### The Orchestrator

The orchestrator is the **deny-by-default gatekeeper** of the principal's data. Its responsibilities:

- **Protect the principal's database** — only the principal (via Ed25519 DID keypair) can authorize mandates; all agent access is scoped and TTL-bounded
- **Dry-run builder** — before execution, the orchestrator constructs the full mandate plan (selected agent, action type, required disclosures, returns) and surfaces it as a Ghost/AwaitingApproval block for explicit approval
- **SD-JWT selective disclosure** — only the minimum properties required by the agent's `requires_disclosure` list are revealed; the query itself travels inside a disclosure envelope, never as a bare parameter
- **Long-horizon memex** — episode history persisted in SQLite (`crates/papillon-shared/src/episode_db.rs`) enables memory-informed agent selection, pre-approval for recurring patterns, and progressive security posture refinement over time
- **LLM-optional** — local catalog agents (200+ in `crates/pap-agents/catalog/`) require no LLM; if the user configures one (Ollama, Bedrock, etc.) the orchestrator uses it to enhance intent detection and outcome synthesis

### AI Optional by Design

Papillon runs the full 6-phase PAP handshake in **WASM** (browser/web build) or **Tauri IPC** (desktop) with zero dependency on any cloud AI service. The `detect_intent()` function in `crates/papillon-shared/src/intent.rs` is a deterministic program — keyword matching + schema.org action classification — not an LLM call. An LLM is an enhancement layer on top of a fully functional protocol runtime.

### Key Architecture

- **Multi-crate Rust monorepo** under `crates/` (pap-core, pap-did, pap-credential, pap-transport, pap-federation, pap-marketplace, pap-proto, pap-webauthn, pap-c)
- **Papillon** (under `apps/papillon/`) is a desktop reference implementation, not marketing material
- **Examples** in `examples/` demonstrate the full protocol surface (search, travel-booking, delegation-chain, payment, networked, federated, webauthn)
- **Python bindings** via PyO3 (`crates/pap-python/`) for broader language support
- **C FFI** (`crates/pap-c/`) — stable cdylib/staticlib layer; basis for C++, C#, and Java bindings
- **M-of-N social recovery** (v0.8.0): `crates/pap-core/src/shamir.rs` (core SSS), `apps/papillon/src/commands/recovery.rs` (Tauri commands), `apps/papillon/frontend/src/components/recovery_setup.rs` (setup wizard)

## Development Standards

- **SOLID principles** apply throughout—composition over inheritance, dependency inversion, single responsibility
- **Comprehensive tests** required for all features, especially cryptographic operations and protocol invariants
- **No mocking or shortcuts** in the core library—implementations must be real and spec-compliant
- **Specification-first**: Reference the RFC-style specification (docs/specification.md) as source of truth
- Decode `did:key` identities, W3C VCs, SD-JWTs, and JSON-LD according to the spec, not convenience

## Core Concepts (Never Remove)

- **Mandate-based delegation** with cryptographic scope/TTL bounds
- **Ephemeral session DIDs** unlinked to principal identity
- **Protocol-enforced context minimization** via SD-JWT selective disclosure
- **Co-signed transaction receipts** containing property references only—never values
- **Progressive decay states** (Active → Degraded → ReadOnly → Suspended)
- No novel cryptography, no central registry, no token economy

## Design System

See DESIGN.md for the complete design system (colors, typography, spacing, schema.org component mapping).

Key rules:
- Purple `#6c5ce7` is the brand color — never remove or replace it
- Wing spectrum colors have semantic meaning (teal=resolved, gold=in-progress, coral=error)
- All JSON-LD content is rendered as text only — never innerHTML
- Fonts: Satoshi (display), DM Sans (body), JetBrains Mono (code/DIDs)

## gstack

For all web browsing tasks, use the `/browse` skill from gstack. NEVER use `mcp__claude-in-chrome__*` tools.

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke office-hours
- Bugs, errors, "why is this broken", 500 errors → invoke investigate
- Ship, deploy, push, create PR → invoke ship
- QA, test the site, find bugs → invoke qa
- Code review, check my diff → invoke review
- Update docs after shipping → invoke document-release
- Weekly retro → invoke retro
- Design system, brand → invoke design-consultation
- Visual audit, design polish → invoke design-review
- Architecture review → invoke plan-eng-review
- Save progress, checkpoint, resume → invoke checkpoint
- Code quality, health check → invoke health

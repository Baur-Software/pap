# Papillion Brochure Page Content

Source content for the `/papillion` GitHub Pages brochure. Convert to HTML matching the `/pap` page design system (Inter + JetBrains Mono, dark theme, indigo/violet gradient).

---

## Hero

**Badge:** v0.3.4
**Badge:** Desktop App
**Badge:** Open Source

# Your agents. Your device. Your rules.

Papillion is the desktop reference implementation of the Principal Agent Protocol. It runs on your machine, stores your data locally, and gives you cryptographic control over every agent interaction. No cloud dependency. No platform account. No trust required.

**CTA:** Download on GitHub
**CTA:** View the Protocol →

**Stats:**
- On-Device LLM (TinyLlama bundled)
- SQLite Memory (receipt-anchored episodes)
- Federated Discovery (no central registry)
- Schema.org Rendering (type-safe, no innerHTML)

---

## Section: THE PROBLEM WITH AGENT APPS

### Every AI assistant stores your data on someone else's server.

Your conversations, your preferences, your behavioral patterns — they live on a platform you don't control. The assistant works for you in theory. In practice, it works for the company that hosts it.

When the platform changes terms, your data goes with it. When the platform gets acquired, your data goes with it. When the platform gets breached, your data goes with it.

Papillion stores everything locally. Your principal keypair, your episode history, your agent profiles — all in a SQLite database on your machine, encrypted at rest with a key derived from your Ed25519 seed. If you lose the seed, the data is unrecoverable. That is the point.

---

## Section: WHAT PAPILLION DOES

### 1. Runs Your Own Orchestrator

Papillion bundles a local LLM (TinyLlama by default, swappable) and runs inference on your device via Candle. Your prompts never leave your machine unless you explicitly delegate to an external agent — and when you do, the PAP handshake controls exactly what that agent sees.

```
[You] → "Find flights from Portland to Tokyo in April"
[Orchestrator] → intent: ReserveAction (FlightReservation)
[Marketplace] → 3 agents found, 1 excluded (requires email)
[Mandate] → scope: ReserveAction, TTL: 1h
[Mandate] → disclosure: departureDate, arrivalDate, origin, destination
[Handshake] → ephemeral session DIDs, SD-JWT, execution, co-signed receipt
[Result] → FlightReservation JSON-LD → rendered as typed card
```

The orchestrator queries your episode store to select the best agent — not by keyword match, but by observed success rate, speed, and minimal disclosure history.

### 2. Remembers What Works (Memex-Style Episode Store)

Every completed agent interaction produces a structured receipt that is persisted to SQLite:

| Field | What It Records |
|-------|----------------|
| action_type | Schema.org action (SearchAction, ReserveAction, etc.) |
| agent_did_hash | SHA-256 of agent DID — never the raw identity |
| outcome | success, failure, or rejected |
| scope_exercised | Which permissions were actually used |
| disclosure_refs | Which properties were disclosed (never values) |
| duration_ms | How long the interaction took |
| decay_state | Current mandate lifecycle state |
| result_json | Full JSON-LD response payload |

After 5+ episodes per agent, Papillion computes:
- **Success rate** — exponential moving average (alpha=0.2)
- **Quality score** — response completeness and relevance
- **Speed profile** — average duration per action type
- **Minimal disclosure set** — intersection of disclosures across all successful runs

This means the orchestrator gets measurably better at selecting agents and calibrating mandates over time. Not because the model improved — because the evidence accumulated.

### 3. Discovers Agents Through Federation

Papillion's marketplace is not an app store. It is a federated peer-to-peer network where operators publish signed agent advertisements.

- **No central registry.** Each operator runs their own registry.
- **Cryptographic verification.** Advertisements are signed by the operator's DID. Invalid or unsigned entries are rejected.
- **Capability-based discovery.** `query_satisfiable(action, available_properties)` returns agents whose disclosure requirements can be met by your available data. Agents that require more than your mandate permits are excluded before negotiation.
- **TLS fingerprint pinning.** Federation peers are verified by certificate fingerprint, not CA chain.
- **Content-hash deduplication.** Duplicate advertisements from multiple peers are merged, not duplicated.

You control which federation peers you trust. You can run a fully local marketplace with zero peers. Or you can join a network of operators and discover agents across organizational boundaries.

### 4. Renders Agent Output as Typed Micro-Apps

Agents return Schema.org JSON-LD. Papillion's rendering engine turns structured data into rich views:

**FlightReservation** → Route arrow with carrier, dates, price
**LodgingReservation** → Hotel card with check-in/out, amenities, price
**SearchResultsPage** → Result list with titles, URLs, snippets
**Answer** → Clean paragraph text (on-device LLM responses)
**Any @type** → Generic renderer classifies fields by shape (date, price, URL, DID, nested object, list)

**The hard invariant: all JSON-LD content is rendered as text only — never innerHTML.**

A `<script>` tag in agent output renders as the text `<script>`. A CSS `@import` renders as the text `@import`. There is no execution surface. Lists are capped at 50 items. Total entries capped at 2,000. The rendering engine cannot be poisoned because it does not interpret — it classifies and displays.

New renderers are registered at runtime via `RendererRegistry`. When a new Schema.org type appears, a new renderer handles it. No code push. No app update. The type system is the extension mechanism.

---

## Section: HOW IT'S BUILT

### Architecture

```
┌─────────────────────────────────┐
│         Leptos Frontend         │  ← WASM, CSR mode
│   (Sidebar, Canvas, Registry,   │
│    Block Renderer, Activity)    │
├─────────────────────────────────┤
│        Tauri IPC Bridge         │  ← Type-safe commands
├─────────────────────────────────┤
│         Tauri Backend           │
│  ┌──────────┬───────────────┐   │
│  │  State   │  Orchestrator │   │
│  │ Manager  │  (PAP Proto)  │   │
│  ├──────────┼───────────────┤   │
│  │ SQLite   │  Federation   │   │
│  │ Episodes │  Client/Srv   │   │
│  ├──────────┼───────────────┤   │
│  │ Candle   │  Marketplace  │   │
│  │ LLM      │  Registry     │   │
│  └──────────┴───────────────┘   │
└─────────────────────────────────┘
```

| Component | Technology | Why |
|-----------|-----------|-----|
| Desktop shell | Tauri 2 | Native performance, small binary, Rust backend |
| Frontend | Leptos 0.7 | Rust → WASM, fine-grained reactivity, no JS runtime |
| LLM inference | Candle (HuggingFace) | On-device, no Python, no server process |
| Database | SQLite (rusqlite) | Single-file, embedded, zero config |
| Protocol | PAP crates | pap-core, pap-did, pap-credential, pap-transport, pap-federation |
| Rendering | RendererRegistry | Trait-based, SOLID-compliant, extensible per @type |

### Design System

The butterfly logo represents the zero-trust boundary — bilateral symmetry where nothing crosses without proof.

- **Purple #6c5ce7** — Brand identity, actions
- **Teal #2ec4a0** — Resolved, trust confirmed
- **Gold #f0a030** — In-progress, agent working
- **Coral #e8706a** — Error, trust broken
- **Fonts:** Satoshi (display), DM Sans (body), JetBrains Mono (DIDs, keys, JSON-LD)

All protocol state is visible in the UI: handshake phase dots, disclosure indicators, decay state badges. Zero-trust is not hidden — it is the interface.

---

## Section: WHAT THIS IS NOT

**Not a cloud service.** There is no Papillion account. No subscription. No backend.

**Not a chatbot wrapper.** Papillion is not a skin over an API. The orchestrator runs locally. The protocol enforces constraints. The memory is receipt-anchored.

**Not locked to one model.** TinyLlama is bundled for out-of-box experience. Swap in Mistral, Llama, Phi, or any GGUF model. The orchestrator doesn't care — it delegates via mandate regardless of the inference backend.

**Not a walled garden.** Federation is built-in. Your Papillion instance can discover and negotiate with agents published by anyone running a PAP-compatible registry.

---

## Section: COMPARISON

| | Papillion | ChatGPT Desktop | Claude Desktop | OpenClaw |
|---|---|---|---|---|
| Data storage | Local SQLite | OpenAI servers | Anthropic servers | Local markdown files |
| Agent identity | W3C DIDs (Ed25519) | Platform tokens | Platform tokens | Config-based |
| Context control | SD-JWT per-field disclosure | All-or-nothing | All-or-nothing | All-or-nothing |
| Agent memory | Receipt-anchored episodes | Platform-managed | Platform-managed | Model-curated text |
| Federation | Built-in (peer-to-peer) | None | None | None |
| UI rendering | Type-safe JSON-LD (no innerHTML) | Platform-controlled | Platform-controlled | Raw HTML canvas |
| Delegation | Cryptographic mandates | N/A | N/A | Session messaging |
| Receipts | Co-signed, property refs only | None | None | None |
| Model lock-in | Any GGUF / Candle model | GPT only | Claude only | Multi-provider |
| License | MIT / Apache 2.0 | Proprietary | Proprietary | MIT |

---

## CTA Banner

### The protocol is the product.

Papillion is not a platform. It is proof that the Principal Agent Protocol works — that agents can transact with cryptographic trust, selective disclosure, and mutual accountability on a desktop machine with no cloud dependency.

Clone it. Run it. Break it. Build on it.

**CTA:** Download on GitHub
**CTA:** Read the Specification
**CTA:** Read the Blog

---

## Footer

Same structure as /pap page. Links to:
- Protocol: /pap
- Specification: docs/specification.md
- Blog: baursoftware.com/blog
- GitHub: github.com/Baur-Software/pap
- License: MIT OR Apache-2.0

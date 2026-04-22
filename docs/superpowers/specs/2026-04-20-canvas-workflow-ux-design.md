# Canvas Workflow UX — Design Spec

**Date:** 2026-04-20
**Status:** Approved for implementation planning
**Scope:** Back face workflow layer + block composition UX for Papillon

---

## Context

Papillon's canvas renders intent-driven agent results as blocks. The existing UX handles individual blocks well — the 6-phase handshake, Ghost → AwaitingApproval → Resolving → Resolved lifecycle, TTL decay, and the front/back face flip are all solid. The gap is **composition**: there is no way to see how blocks relate to each other, and no way to design a multi-agent workflow before running it.

The two problems are equally painful:
1. **Reactive opacity** — when block B uses `{{block:A}}` as input, that dependency is invisible on the canvas.
2. **No intent-first design** — you can only add blocks one at a time. There is no way to sketch "search → lookup → synthesize" before firing it.

The solution is to make the **back face the workflow layer** — a live, interactive node graph that is both a map of what already ran and a design surface for what will run next.

### The right mental model

This is OAuth — but decentralized and reversed. OAuth: the service defines scope strings, a central server mediates, you click Allow. PAP: the principal holds the SD-JWT commitment, agents declare exactly which `schema:Type.property` paths they need, the principal selectively reveals specific properties. The workflow graph *is* the consent screen — built from cryptographic property paths, not vague scope strings like `read:profile`. No central server. No platform in the middle.

---

## Design

### 1. Back Face: Two Modes in the Workflow Tab

The existing back face has three tabs: Sources / Build / History. The **Build tab becomes the Workflow tab** with two sub-modes toggled by a MAP / DESIGN toggle in the tab bar.

#### Map Mode (default)

Auto-generated live dependency graph of the current canvas. Always reflects the actual state of blocks.

- Each resolved or in-progress block is a node
- `{{block:ID}}` references in prompts become directed edges
- Post-execution, edges are reconstructed from receipt `property_refs`
- Node color follows the wing spectrum: teal = resolved, gold = running/awaiting, coral = failed, purple = pending/outcome
- Click any node to jump to that block on the front face
- TTL decay badge visible per node (active → degraded → readonly)
- No editing in Map mode — it is a read-only mirror of what the protocol produced

Map mode is free — you get it automatically from every prompt you run. Zero friction.

#### Design Mode

An intent-first workflow builder. Blank canvas + tools strip. Build a workflow before running it.

**Tools strip (left column):**
- 🤖 Agent — add a new agent node
- ⬡ Synthesize — add a synthesizer node (BriefingDoc / FreeText / FAQ / Timeline / Outline)
- 📝 Note — add a text note node
- 💾 Save — save as a named pipeline
- ▶ Run — execute the workflow; creates blocks on the front face in real time

**No agent palette.** Agents are resolved at run time from intent. When you add an Agent node a small inline text field appears: "what should this step do?" The orchestrator resolves the matching agent(s) at execution time via the marketplace `query_satisfiable` call — the principal never browses a catalog.

---

### 2. Agent Nodes — Property-Level Joins

Agent nodes are styled like database tables in a query designer (Access, Sequel Pro). The interaction is the same: drag from a property row on one node to a property row on another. That line *is* the disclosure.

#### Node anatomy

A node is a complete step definition: intent + agent (resolved at run) + property wires (disclosure) + render template.

```
┌──────────────────────────┐
│ 🤖  Flight Search        │  ← agent name (humanized), pap:// URI
│     pap://agents/flights  │
├──────────────────────────┤
│ RECEIVES FROM PRINCIPAL   │  ← requires_disclosure ports (inputs, left)
│ ○ Departure Date          │     schema:Flight.departureDate (required)
│ ○ Origin City             │     schema:Place.name (optional)
├──────────────────────────┤
│ OUTPUTS                   │  ← returns ports (right-edge dots)
│ Departure Date        ●   │
│ Destination City      ●   │     toLocation.name — already in FlightReservation
│ Reservation           ●   │
├──────────────────────────┤
│ RENDER AS  [FlightCard ▾] │  ← template picker (optional; auto = RendererRegistry default)
└──────────────────────────┘
```

- **Human label** on each row (e.g. "Departure Date"), schema ref in small monospace below
- **Input ports** (left-edge dot): filled = wired, empty = unwired or standalone
- **Output ports** (right-edge dot): filled = connectable, absent = no port exists
- **Standalone capable**: every node runs as its own block even with no wires
- **Render As**: optional template picker at the bottom of the node. Defaults to `auto` (RendererRegistry dispatch). Can be set to any shipped template or user-defined template from TemplateLibrary for that schema type. Saved as part of the pipeline definition — every run renders consistently with the chosen template.

The template picker only shows templates compatible with the agent's `returns` schema type. An ICP pipeline node returning `schema:Organization` would show `IcpCard`, `OrgProfile`, `GenericCard`, etc. — not flight templates.

#### Scaling from single block to automated pipeline

The same node definition scales across all use cases:

| Mode | How it works |
|---|---|
| Single block | One prompt, one handshake, Map mode shows one node. No design step needed. |
| Composed | `{{block:ID}}` refs in prompts; Map mode derives edges from receipts. No design needed. |
| Designed workflow | Design mode, explicit property wires, template per node, saved pipeline. |
| Automated (e.g. ICP pipeline) | Saved pipeline, all wires memex-pre-approved, fires end-to-end silently. Map mode shows execution history. |

The pipeline execution engine (`commands/pipeline.rs`) already handles topological sort, parallel branches, and synthesizer nodes. Design mode is a visual editor for what that system already supports — no new execution model needed.

#### Property-level connectability

Only schema-compatible paths are connectable. The rule:

> If the SD-JWT commitment for the upstream agent's return type does not contain a claim matching the downstream agent's `requires_disclosure` path, **no port is rendered for that property**. The wire is cryptographically impossible and the graph does not offer it.

This means:
- `FlightReservation.arrivalAirport` (type `schema:Airport`) cannot wire to `Place.name` (type `xsd:string`) — **no port rendered, no wire possible**
- `FlightReservation.toLocation.name` (type `xsd:string`) wires cleanly to `Place.name` — **port rendered, wire connectable**
- The principal is never asked to arbitrate impossible type mismatches — the protocol already made them impossible

Port rendering is computed from the agent's marketplace advertisement (`requires_disclosure` + `returns`) cross-referenced against the SD-JWT commitment structure at graph-build time, before any handshake runs.

#### Edge states

| State | Color | Meaning |
|---|---|---|
| Confirmed | Teal solid | Schema types satisfy `requires_disclosure`; ready to run |
| Proposed | Gold dashed | No memex record for this `(output_type, input_type, agent_did)` triple; will pause for principal approval at run time |
| Blocked | Coral | Disclosure would exceed mandate scope; cannot connect |
| Unconnected | Grey dashed | Node runs standalone with its own prompt |

Label on each edge shows the human property name + schema ref of what flows across it.

---

### 3. Memex-Backed Approval Flow

Approvals are not per-session interruptions by default. The episode DB (`papillon-shared/src/episode_db.rs`) backs every approval decision.

#### Auto-approval (silent, memex-remembered)

When the principal has previously approved a property wire for a given `(output_schema_type, input_schema_type, agent_did)` triple, the orchestrator auto-approves silently per spec §13.4. The graph shows a 🧠 "remembered" badge on that edge — visible confirmation that a prior approval is being honoured, not a new consent event.

No interruption. No approval card. The workflow runs through.

#### New approval (inline card, not modal)

When a wire has no memex record — first time seeing this agent, or first time this property combination has been wired — the downstream agent's handshake pauses at the existing `AwaitingApproval` gate. An approval card surfaces **inline in the graph at the paused edge**, not as a modal over the whole UI.

The card shows:
- Agent identity (name, `pap://` URI, provider, TEE attestation status, receipt count)
- Plain-English description of what will be disclosed: "Your departure date" and "Your destination city"
- What will NOT be seen (name, email, payment, full itinerary, etc.)
- Mandate duration and renewal policy
- Three actions: **Allow once** / **Always allow 🧠** / **Deny**

"Always allow" writes a pre-approval to the episode DB keyed by `(output_type, input_type, agent_did)` with TTL and value limits per §13.4. Subsequent encounters anywhere on the agentic web auto-approve silently.

Upstream agents that already resolved keep their blocks live on the front face. The approval interrupt is surgical — only the blocked edge pauses.

#### The approval question

The principal is deciding: *"Do you want to send your departure date and destination city to this hotel agent?"* — not "do these schema types match." The protocol enforced schema compatibility already. The approval card speaks in plain English about real data. The graph shows exactly which wire is being approved.

---

### 4. Front Face / Back Face Coordination During Execution

When a workflow runs from Design mode:

1. Front face pre-creates skeleton blocks for each agent node (stable IDs: `pipeline-{id}-{node_id}`)
2. Back face shows the graph animating: edges pulse with a traveling dot as disclosure flows
3. Each node transitions through the wing-spectrum colors as its block state changes
4. When an approval interrupt fires, the paused edge highlights gold and the approval card appears in the graph — the front face shows the skeleton block in `AwaitingApproval` state simultaneously
5. After approval, the edge resumes (pulse animation), and both faces update together
6. When a node resolves, its front-face block fills in with rendered content; back-face node turns teal

The two faces stay in sync via the existing `CanvasEvent` typed event system. No new event types needed — `BlockPhaseChanged`, `BlockResolved`, `BlockFailed` already carry the block ID, and the graph subscribed to those IDs.

---

### 5. Standalone Blocks (unchanged)

Running a single prompt with no workflow graph is unchanged. It creates one block, goes through the existing handshake, gets an `AwaitingApproval` card in the block itself if needed. Map mode on the back face will show it as a single unconnected node. Nothing regresses.

---

## Key Files to Modify

| File | What changes |
|---|---|
| `apps/papillon/frontend/src/pages/canvas.rs` | Add MAP/DESIGN toggle state; coordinate flip with workflow tab |
| `apps/papillon/frontend/src/state/canvas.rs` | Add `WorkflowGraph` state (nodes, edges, edge states); derive graph from block events |
| `apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs` | Rebuild as the Map + Design mode graph canvas |
| `apps/papillon/frontend/src/components/block_renderer/mod.rs` | No change to block rendering itself |
| `apps/papillon/frontend/src/components/pipeline_builder_tab.rs` | Merge into / replace with new Design mode canvas |
| `apps/papillon/frontend/src/pages/settings/templates_tab/` | Feed TemplateLibrary into node template picker (filter by schema type) |
| `apps/papillon/frontend/styles/main.css` | New CSS for node/edge/port components, pulse animation, approval card inline state |
| `crates/papillon-shared/src/types.rs` | Add `WorkflowNode` (with `template_override: Option<String>`), `WorkflowEdge`, `EdgeState`, `PortRef` types |
| `crates/papillon-shared/src/episode_db.rs` | Add auto-approval lookup by `(output_type, input_type, agent_did)` |
| `apps/papillon/src/commands/pipeline.rs` | Emit edge-level events for approval interrupts; expose port compatibility check |

---

## Out of Scope

- Animated SVG edge routing (use CSS flexbox row alignment for now — nodes and edges in the same row guarantee vertical alignment without SVG coordinate math)
- Agent marketplace browse UI (agents resolve from intent at run time, no palette)
- DID display in node headers (humanized name + `pap://` URI only; DID available on the back face's Sources tab for those who want it)
- Multi-canvas workflow composition (single canvas scope for this iteration)

---

## Verification

1. **Map mode** — run two prompts where the second uses `{{block:ID}}` from the first. Flip to back face. Verify the dependency edge renders between the two nodes.
2. **Design mode** — add two agent nodes, verify ports populate from advertisement data. Drag a valid property wire; verify it shows teal confirmed. Attempt to wire an incompatible property; verify no port is rendered for it.
3. **Approval flow** — wire two agents with no memex record. Run. Verify the downstream node pauses, the approval card appears inline in the graph, and the front face shows `AwaitingApproval` simultaneously. Approve; verify both faces update and the workflow continues.
4. **Memex auto-approve** — run the same workflow a second time. Verify the 🧠 badge appears and no approval card surfaces.
5. **Standalone regression** — run a single prompt with no graph. Verify existing block lifecycle is unchanged.

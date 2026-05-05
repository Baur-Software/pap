# Registry Agent Editor — Design Spec
**Date:** 2026-05-03  
**Status:** Draft

---

## Problem

The Registry page exposes schema.org vocabulary directly on every surface — action types, return types, disclosure requirements. This is unfamiliar to anyone who isn't a schema.org author. Separately, the page shows agents but not what backs them: a CLI, an HTTPS endpoint, or a sub-agent DID. Most importantly, the page treats the registry as a browsing surface when it is fundamentally an authoring and publishing surface — the PAP answer to an API gateway.

---

## What the Registry Actually Is

The registry is where agents are defined, signed, and published into the federation. It behaves like a marketplace to consumers (via federation), but from the operator's perspective it is an API gateway: you define the agent contract, point it at an execution target, and the federation protocol handles distribution and trust. An agent advertisement signed by this node's Ed25519 DID keypair is the publishable unit; peers verify that signature when they ingest the advertisement.

---

## Design

### Layout: Postman-style editor

Three regions:

1. **Left sidebar** — agent list, grouped by lifecycle state (Published / Draft / Unpublished). Search bar at top. "+ New" button creates a blank draft.
2. **Main editor** — full agent authoring surface.
3. **Bottom panel** — live JSON-LD advertisement preview. Always visible. Sign & Save lives here.

### Sidebar

- Agents grouped into three sections: **Published**, **Draft**, **Unpublished**
- Each item shows: state indicator dot, agent name, derived verb phrase
- Active item is highlighted with purple left border
- "+ New" creates a nameless draft and opens it in the editor

### Agent Bar (top of editor, analogous to Postman's URL bar)

Three elements in a single row:

| Element | Description |
|---------|-------------|
| **Action selector** | Dropdown of plain-English verbs derived from schema.org actions — "Search", "Book", "Buy", "Reserve", "Review", "Create", "Find", etc. Selecting one sets `action` on the advertisement. |
| **Agent name input** | Editable name field. Large, prominent. This is identity. |
| **State badge** | Read-only. Shows current lifecycle state with animated dot for Published. |

The action selector uses `heck::ToTitleCase` to strip `schema:` prefix and `Action` suffix for display. The underlying advertisement stores the full `schema:SearchAction` URI.

### Tabs

Five tabs below the agent bar:

| Tab | Content |
|-----|---------|
| **Input** | Dynamic property builder — the `configurable_properties` of the agent. Each property has: name, type, default, min/max (for numeric), required toggle. Types are the full `PropertyValueSpecification` vocabulary (string, number, boolean, enum, date, datetime, URL, duration, geo, array, object — not a fixed 4-item list). Row-based table with + Add Property and × delete per row. |
| **Returns** | What schema.org type(s) this agent produces. Shown as plain-English tags (e.g., "Software Application" not "schema:SoftwareApplication"). Converted via `heck` at render time. "+ Add type" adds a tag. |
| **Disclosure** | What principal data this agent requires access to. Plain-English tags (e.g., "Location", "Email"). Empty state shows "No disclosure required" — a trust signal, displayed prominently. |
| **Endpoint** | The execution target. Method selector (GET/POST/etc) + URL field. Below: response JSONPath field, response schema type. This is where `Local` vs `Remote` is expressed — `file://` prefix renders as Local badge; `https://` renders as Remote; a DID renders as Sub-agent. The badge is derived from the URL scheme, not a separate field. |
| **Settings** | Provider name, description (used as primary display text when present, overrides derived verb phrase), version, LLM instructions, `llm_instructions` textarea. |

### Execution Target

`ExecutionTarget` is derived from `[endpoint].url_template` at deserialization in `papillon-shared`:

| URL scheme | ExecutionTarget variant | Badge |
|------------|------------------------|-------|
| `https://` or `http://` | `Remote(String)` | Remote (blue) |
| `file://` | `Local(String)` | Local (teal) |
| `did:` or `pap://` | `SubAgent(String)` | Sub-agent (gold) |

`AgentInfo` in `papillon-shared` gains `execution_target: ExecutionTarget`. No new TOML field — derived at load time. All 200+ existing catalog agents have `[endpoint]` with `https://` URLs so they deserialize to `Remote` automatically with zero TOML changes.

### Schema.org → Plain English

`schema_phrase(s: &str) -> String` in `papillon-shared`:

1. Strip `schema:` prefix
2. Strip trailing `Action` (for action types only)
3. Run through `heck::ToTitleCase`

Examples: `schema:SearchAction` → `"Search"`, `schema:SoftwareApplication` → `"Software Application"`, `schema:LodgingReservation` → `"Lodging Reservation"`.

Uses `heck` crate already present in the dependency tree. No static translation table.

**Fallback rule:** If `description` is present on the agent, it is shown as the primary display text in place of the derived phrase. Derived phrase is the fallback.

### Lifecycle States

| State | Meaning | Editor action |
|-------|---------|---------------|
| **Draft** | Unsigned, not visible to peers | "Sign & Publish" |
| **Published** | Signed, advertised to federation | "Unpublish" |
| **Unpublished** | Signed but withdrawn from federation | "Re-publish" |

Signing is the act that transitions Draft → Published. It uses the node's Ed25519 DID keypair per the PAP spec. The UI does not gate signing on JSON-LD review — "View JSON-LD" is a transparency affordance beside the action button, not a required step.

### Bottom Panel — JSON-LD Preview

- Always visible, 200px height, collapsible
- Live preview of the advertisement JSON-LD as the user edits
- Color-coded syntax: keys (blue), strings (purple), numbers (teal), braces (dim)
- Shows the node's DID in the `did` field
- "Sign & Save" button (primary) and state-appropriate secondary action (Unpublish / Re-publish) live here

---

## Data Layer Changes

### `papillon-shared`

1. Add `ExecutionTarget` enum:
   ```rust
   pub enum ExecutionTarget {
       Remote(String),
       Local(String),
       SubAgent(String),
   }
   ```

2. Add `schema_phrase(s: &str) -> String` using `heck::ToTitleCase`

3. `AgentInfo` gains:
   - `execution_target: ExecutionTarget` — derived at deserialization
   - `lifecycle: AgentLifecycle` — `Draft | Published | Unpublished`

### TOML catalog

No changes required. All existing agents deserialize correctly. `execution_target` is derived, not declared.

### Registry app (`apps/registry`)

- Agent list and detail views use `schema_phrase()` for display
- Agent list shows `ExecutionTarget` badge
- Lifecycle state surfaced from signing status in DB

### Papillon frontend (`apps/papillon/frontend`)

- `pages/registry.rs`: replace current browse-only layout with sidebar + editor layout
- `components/registry/agent_card.rs`: replace with `agent_editor.rs` — full tabbed editor component
- `components/registry/browser.rs`: becomes peer browser, accessible via "Peers (N)" button in topbar
- `state/registry.rs`: extend with `selected_agent`, `edit_draft`, lifecycle transition commands

---

## Out of Scope

- Peer agent browsing redesign (separate feature — peers surface via "Peers" button, not the main editor)
- Full property type builder beyond current `PropertyValueSpecification` types (known sub-problem, architecture supports expansion)
- LLM-assisted agent authoring
- Import from OpenAPI spec

---

## Success Criteria

- A developer can open the registry, create a new agent, define its input properties and endpoint, and sign & publish it without seeing a single `schema:` URI
- Every existing catalog agent loads with correct execution target badge and plain-English verb phrase — zero TOML changes
- The JSON-LD preview matches what peers will verify when they ingest the advertisement

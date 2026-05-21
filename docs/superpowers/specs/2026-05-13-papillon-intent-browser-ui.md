# Papillon Intent Browser UI - Design Specification

**Date:** 2026-05-13  
**Status:** Draft  
**Authors:** Claude + Todd Baur

## Executive Summary

Transform Papillon from a protocol demonstration into the browser for the agentic age. Users navigate intent spaces (not webpages), delegate to agents (legal authority, not AI), and see results rendered via schema.org vocabulary (no UI over the wire). The core UX shift: canvas tabs for parallel intent streams, two-sided canvas (render primary, workflow on-demand), and dynamic disclosure forms generated from agent advertisements.

## Core Principles

1. **Intent-first, not protocol-first** - Users state what they want, protocol transparency is progressive disclosure
2. **Agents are legal delegates** - Authority delegation with cryptographic mandates, not AI chatbots
3. **Schema.org as universal contract** - Data agents and UI agents communicate via standard vocabulary
4. **Results before workflow** - Render side is primary view, workflow side is control center when needed
5. **Ghost blocks are result previews** - Show aggregated output shape from multiple agents, not per-agent plans
6. **Canvas as persistent intent space** - Not ephemeral like browser tabs, survives sessions with cryptographic provenance

## Problem Statement

Current Papillon UI obscures the "agentic browser" vision:

- Canvas selection via dropdown (hidden navigation)
- Workflow pipeline buried in flip-side (discoverability problem)
- Per-agent approval gates interrupt flow (approval should be at intent-level, not agent-level)
- No visual distinction between intent streams when multiple are active
- Protocol complexity exposed too early (6-phase handshake visible before user needs it)

## Goals

### Must Have (v1.0)

- Browser-style tab bar for canvas navigation
- Two-sided canvas: render side (primary) + workflow side (on-demand panel)
- Agent curation UI with trust badges (on-device vs marketplace)
- Dynamic disclosure form generation from `AgentAdvertisement.requires_disclosure`
- Ghost block as unified result preview (not per-agent)
- Toast notifications for approval requests (non-blocking)

### Should Have (v1.1)

- Workflow panel shows pipeline graph with pap://did linkage
- Block provenance visualization (which agents contributed to result)
- UI agent marketplace (agents that render schema.org vocabulary)
- Pre-approval for trusted on-device agents

### Could Have (v2.0)

- WASM UI agent support (custom visualizations with sandboxing)
- Multi-canvas synthesis (link blocks across canvases)
- Collaborative canvas sharing (multiple principals, shared intent space)

## Architecture

### Existing Infrastructure (Reuse)

Papillon already has the foundation:

**State Management** (`apps/papillon/frontend/src/state/canvas.rs`):

- `canvas_side: RwSignal<CanvasSide>` - Front/Back flip container
- `hitl_pending: RwSignal<Option<HitlRequest>>` - HITL gate system
- `canvas_messages: RwSignal<Vec<CanvasMessageRecord>>` - Chat thread persistence
- `workflow_graph: RwSignal<WorkflowGraph>` - Pipeline graph state
- `CanvasEvent` enum - Typed event bus for block lifecycle

**Approval Flow** (`apps/papillon/src/commands/canvas/approval.rs`):

- `canvas_plan_prompt()` - Creates `IntentPlan` with union of `requires_disclosure`
- `AgentCandidate` list - Per-agent disclosure requirements
- Auto-approve for zero-disclosure agents
- Emits `AwaitingApproval` block state

**Agent Discovery** (`crates/pap-marketplace/src/advertisement.rs`):

- `AgentAdvertisement` - Schema.org vocabulary with `requires_disclosure`, `returns`, `configurable_properties`
- Trust metadata via `OperatorMetrics`
- Signature verification for marketplace agents

### New Components

#### 1. Tab Bar (`apps/papillon/frontend/src/components/canvas_tab_bar.rs`)

**Visual Design:**

- Horizontal bar below address bar (48px height)
- 4 visible tabs max (180px each), LRU eviction to overflow dropdown
- Active tab: 2px purple bottom border, bold text
- Inactive tabs: muted gray, brighten on hover
- New tab `+` button pinned right
- Overflow `⋯` dropdown shows full canvas list with timestamps

**State Integration:**

```rust
#[component]
pub fn CanvasTabBar(canvas_state: CanvasState) -> impl IntoView {
    let canvases = canvas_state.canvases;
    let current_id = canvas_state.current_canvas_id;
    
    // First 4 by updated_at desc
    let visible_tabs = create_memo(move |_| {
        let mut sorted = canvases.get().clone();
        sorted.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        sorted.into_iter().take(4).collect::<Vec<_>>()
    });
    
    // Remainder in overflow
    let overflow_canvases = create_memo(move |_| {
        let mut sorted = canvases.get().clone();
        sorted.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        sorted.into_iter().skip(4).collect::<Vec<_>>()
    });
    
    // Click handler
    let switch_canvas = move |id: String| {
        canvas_state.current_canvas_id.set(Some(id));
    };
    
    view! {
        <div class="canvas-tab-bar">
            <For each=visible_tabs key=|c| c.id.clone() let:canvas>
                <CanvasTab canvas=canvas on_click=switch_canvas />
            </For>
            <button class="new-tab-btn" on:click=move |_| {
                canvas_state.new_canvas();
            }>+</button>
            <Show when=move || overflow_canvases.get().len() > 0>
                <OverflowDropdown canvases=overflow_canvases />
            </Show>
        </div>
    }
}
```

**Tab Title Source:**

- `canvas.name` (user-editable via double-click inline rename)
- Auto-generated from first prompt via `auto_name_from_prompt()` (already exists)
- Truncate to 20 chars, full name in tooltip

**Keyboard Shortcuts:**

- `Ctrl+T` → `canvas_state.new_canvas()`
- `Ctrl+W` → `canvas_state.delete_canvas(current_id)`
- `Ctrl+Tab` / `Ctrl+Shift+Tab` → cycle through visible tabs
- `Ctrl+1-4` → jump to tab by index

#### 2. Workflow Panel (`apps/papillon/frontend/src/components/workflow_panel.rs`)

**Layout:**

- Right-side drawer (400px width), slides in from right
- Hidden by default, triggered by:
  - Toast notification click
  - Block workflow badge click (🪽 icon on rendered blocks)
  - Keyboard shortcut `Ctrl+\`
- Persistent chat thread at top (150px scrollable)
- Agent curation section (middle, dynamic height)
- Disclosure form footer (sticky, 120px)

**Sections:**

##### Chat Thread

```rust
#[component]
pub fn WorkflowChatThread(canvas_state: CanvasState) -> impl IntoView {
    let messages = canvas_state.canvas_messages;
    
    view! {
        <div class="workflow-chat">
            <For each=messages key=|m| m.id.clone() let:msg>
                <div class="chat-message" class:user=msg.role=="user">
                    <span class="role">{msg.role}</span>
                    <span class="text">{msg.content}</span>
                    <span class="timestamp">{format_timestamp(msg.timestamp)}</span>
                </div>
            </For>
        </div>
    }
}
```

##### Agent Curation

```rust
#[component]
pub fn AgentCurationList(plan: IntentPlan) -> impl IntoView {
    let (selected_agents, set_selected_agents) = create_signal(
        plan.candidates.iter()
            .filter(|c| c.did == plan.selected_agent_did.as_ref().unwrap())
            .map(|c| c.did.clone())
            .collect::<Vec<_>>()
    );
    
    view! {
        <div class="agent-curation">
            <h3>"Select Agents"</h3>
            <For each=move || plan.candidates.clone() key=|c| c.did.clone() let:candidate>
                <AgentCurationCard 
                    agent=candidate 
                    selected=selected_agents 
                    on_toggle=move |did: String| {
                        set_selected_agents.update(|s| {
                            if s.contains(&did) {
                                s.retain(|d| d != &did);
                            } else {
                                s.push(did);
                            }
                        });
                    }
                />
            </For>
        </div>
    }
}

#[component]
pub fn AgentCurationCard(
    agent: AgentCandidate,
    selected: ReadSignal<Vec<String>>,
    on_toggle: impl Fn(String) + 'static,
) -> impl IntoView {
    let is_on_device = agent.did.starts_with("did:key:"); // Simplified detection
    let is_selected = create_memo(move |_| selected.get().contains(&agent.did));
    
    view! {
        <div class="agent-card" class:selected=is_selected>
            <input 
                type="checkbox" 
                checked=is_selected 
                on:change=move |_| on_toggle(agent.did.clone())
            />
            <div class="agent-info">
                <span class="agent-name">{agent.name.clone()}</span>
                <span class="agent-did">{truncate_did(&agent.did)}</span>
                <Show when=move || is_on_device>
                    <span class="trust-badge on-device">"On-Device"</span>
                </Show>
            </div>
            <div class="disclosure-preview">
                <span class="property-count">
                    {agent.requires_disclosure.len()} " properties"
                </span>
            </div>
        </div>
    }
}
```

##### Dynamic Disclosure Form

```rust
#[component]
pub fn DisclosureForm(
    plan: IntentPlan,
    selected_agents: ReadSignal<Vec<String>>,
) -> impl IntoView {
    // Union of requires_disclosure from selected agents
    let union_disclosure = create_memo(move |_| {
        let selected = selected_agents.get();
        let mut props = Vec::new();
        for candidate in &plan.candidates {
            if selected.contains(&candidate.did) {
                for prop in &candidate.requires_disclosure {
                    if !props.contains(prop) {
                        props.push(prop.clone());
                    }
                }
            }
        }
        props
    });
    
    // Form field state (keyed by property path)
    let (field_values, set_field_values) = create_signal(std::collections::HashMap::new());
    
    view! {
        <div class="disclosure-form">
            <h4>"Required Properties"</h4>
            <For each=union_disclosure key=|p| p.clone() let:property>
                <DisclosureField 
                    property=property 
                    value=field_values 
                    on_change=set_field_values 
                />
            </For>
            <button 
                class="approve-btn"
                on:click=move |_| {
                    // Call canvas_approve_plan with selected agents + field values
                    approve_plan(plan.clone(), selected_agents.get(), field_values.get());
                }
            >
                "Disclose & Execute (" {move || selected_agents.get().len()} " agents)"
            </button>
        </div>
    }
}

#[component]
pub fn DisclosureField(
    property: String,
    value: ReadSignal<HashMap<String, String>>,
    on_change: WriteSignal<HashMap<String, String>>,
) -> impl IntoView {
    // Parse schema.org property path (e.g., "schema:Person.name")
    let field_type = infer_field_type(&property); // "text" | "date" | "email" | "url"
    let label = humanize_property(&property); // "Person Name"
    
    view! {
        <div class="disclosure-field">
            <label>{label}</label>
            <input 
                type=field_type
                placeholder=label
                on:input=move |ev| {
                    on_change.update(|map| {
                        map.insert(property.clone(), event_target_value(&ev));
                    });
                }
            />
        </div>
    }
}
```

**Why:** This matches existing `canvas_plan_prompt()` which already builds `IntentPlan` with union disclosure. We're just surfacing it in UI instead of auto-approving.

#### 3. Toast Notification System (`apps/papillon/frontend/src/components/approval_toast.rs`)

**Visual Design:**

- Fixed position: bottom-right corner, 360px width
- Stacks vertically (max 3 visible, older ones auto-dismiss)
- Purple accent border, white background (dark mode: dark purple bg)
- Shows: agent name, action type, property count, [APPROVE] / [VIEW DETAILS] buttons

```rust
#[component]
pub fn ApprovalToast(request: HitlRequest, canvas_state: CanvasState) -> impl IntoView {
    view! {
        <div class="approval-toast">
            <div class="toast-header">
                <span class="icon">"🪽"</span>
                <span class="agent-name">{request.agent_name}</span>
            </div>
            <div class="toast-body">
                <span class="action">{humanize_action(&request.action_type)}</span>
                <span class="disclosure-count">
                    "Needs " {request.disclosure_props.len()} " properties"
                </span>
            </div>
            <div class="toast-actions">
                <button 
                    class="approve-quick"
                    on:click=move |_| {
                        // Auto-approve with defaults if zero-disclosure
                        // Otherwise open workflow panel
                        if request.disclosure_props.is_empty() {
                            quick_approve(&request);
                        } else {
                            canvas_state.canvas_side.set(CanvasSide::Back);
                        }
                    }
                >
                    "APPROVE"
                </button>
                <button 
                    class="view-details"
                    on:click=move |_| {
                        canvas_state.canvas_side.set(CanvasSide::Back);
                    }
                >
                    "VIEW DETAILS"
                </button>
            </div>
        </div>
    }
}
```

**Integration:**

- Triggered when `canvas_state.hitl_pending` is set
- Dismisses on approval/rejection or after 30s timeout
- Multiple toasts stack vertically with 8px gap

#### 4. Ghost Block Enhancement (`apps/papillon/frontend/src/components/block_renderer/ghost.rs`)

**Current State:** Ghost blocks likely render as empty placeholders.

**Enhanced Design:**

- Show skeleton preview of aggregated result shape
- Use block characters `█` for property values
- Display schema.org type icon + property count
- Multi-agent indicator: "From 3 agents: Expedia, Google Flights, Kayak"

```rust
#[component]
pub fn GhostBlockRenderer(plan: IntentPlan) -> impl IntoView {
    let primary_return_type = plan.returns.first().unwrap_or(&"schema:Thing".to_string()).clone();
    let schema_icon = get_schema_icon(&primary_return_type);
    
    view! {
        <div class="ghost-block">
            <div class="ghost-header">
                <span class="schema-icon">{schema_icon}</span>
                <span class="schema-type">{primary_return_type}</span>
                <span class="agent-count">
                    "From " {plan.candidates.len()} " agents"
                </span>
            </div>
            <div class="ghost-skeleton">
                // Render skeleton based on schema type
                <SkeletonPreview schema_type=primary_return_type />
            </div>
        </div>
    }
}

#[component]
pub fn SkeletonPreview(schema_type: String) -> impl IntoView {
    // Hardcoded skeletons for common types, generic fallback
    match schema_type.as_str() {
        "schema:FlightReservation" => view! {
            <div class="skeleton-flight">
                <div class="field"><span class="label">"Flight:"</span> <span class="value">"████ ████"</span></div>
                <div class="field"><span class="label">"Price:"</span> <span class="value">"$███"</span></div>
                <div class="field"><span class="label">"Duration:"</span> <span class="value">"█h ██m"</span></div>
                <div class="field"><span class="label">"Departure:"</span> <span class="value">"███ → ███"</span></div>
            </div>
        },
        _ => view! {
            <div class="skeleton-generic">
                <div class="field">"████████████"</div>
                <div class="field">"██████"</div>
                <div class="field">"████████"</div>
            </div>
        }
    }
}
```

**Why:** Ghost blocks are result previews, not agent plans. Show what the user will get, not how it will be fetched.

### Component Hierarchy

```
App
├─ TopBar
│  ├─ InlinePrompt (address bar)
│  └─ ProfileAvatar
├─ CanvasTabBar (NEW)
│  ├─ CanvasTab (x4 visible)
│  ├─ NewTabButton
│  └─ OverflowDropdown
├─ CanvasFlipContainer (EXISTING)
│  ├─ CanvasSurface (Front - render side)
│  │  ├─ BlockRenderer (multiple blocks)
│  │  └─ ApprovalToast (NEW - overlays)
│  └─ WorkflowPipeline (Back - workflow side) (ENHANCED)
│     ├─ WorkflowChatThread (NEW)
│     ├─ AgentCurationList (NEW)
│     └─ DisclosureForm (NEW)
└─ WorkflowPanel (NEW - slide-in drawer, alternative to flip)
   ├─ WorkflowChatThread
   ├─ AgentCurationList
   └─ DisclosureForm
```

**Decision Point:** Should workflow be flip-side (Back) or slide-in panel?

**Recommendation:** Start with slide-in panel. Flip-side already exists but is used for pipeline graph visualization. Panel allows:

- Render side stays full-width
- Panel can overlay without losing render context
- Easier progressive disclosure (panel closed by default)
- Flip-side becomes dedicated pipeline graph view (power user feature)

### Data Flow

```
1. User types prompt in address bar
   ↓
2. detect_intent() → classify action + preferred agents
   ↓
3. canvas_plan_prompt() → resolve top 3 candidates
   ↓
4. IntentPlan emitted with:
   - union_disclosure (merged from all candidates)
   - AgentCandidate list
   - primary agent selection
   ↓
5. BlockState::AwaitingApproval created
   ↓
6. Toast notification appears + workflow panel button enabled
   ↓
7. User clicks "VIEW DETAILS" → workflow panel slides in
   ↓
8. Agent curation UI shows candidates with trust badges
   ↓
9. User selects agents (checkboxes), fills disclosure form
   ↓
10. "Disclose & Execute" → canvas_approve_plan(selected_agents, field_values)
    ↓
11. Parallel handshakes spawn (one per selected agent)
    ↓
12. BlockState::Resolving → phases 1-6 animate
    ↓
13. Results aggregate → BlockState::Resolved or BlockState::Outcome
    ↓
14. Render side shows final result via schema.org renderer
```

## Implementation Plan

### Phase 1: Tab Bar (Foundational)

**Files:**

- `apps/papillon/frontend/src/components/canvas_tab_bar.rs` (new)
- `apps/papillon/frontend/src/components/topbar.rs` (integrate tab bar below address bar)
- `apps/papillon/frontend/src/state/canvas.rs` (no changes needed, already has canvases vec)

**Tasks:**

1. Create `CanvasTabBar` component with 4 visible tabs + overflow
2. Wire click handlers to `canvas_state.current_canvas_id`
3. Implement keyboard shortcuts (Ctrl+T/W/Tab)
4. Add LRU sorting by `updated_at`
5. Style active/inactive states with purple accent

**Estimated:** 1 day

### Phase 2: Workflow Panel (Core UX Shift)

**Files:**
- `apps/papillon/frontend/src/components/workflow_panel.rs` (new)
- `apps/papillon/frontend/src/components/workflow_chat_thread.rs` (new)
- `apps/papillon/frontend/src/components/agent_curation_list.rs` (new)
- `apps/papillon/frontend/src/components/disclosure_form.rs` (new)
- `apps/papillon/frontend/src/state/canvas.rs` (add `workflow_panel_open: RwSignal<bool>`)

**Tasks:**

1. Create slide-in panel component (400px width, right-side)
2. Build chat thread viewer (read from `canvas_messages`)
3. Build agent curation cards with trust badges
4. Build dynamic disclosure form generator (parse `requires_disclosure`)
5. Wire "Disclose & Execute" to `canvas_approve_plan()`
6. Add keyboard shortcut (Ctrl+\) to toggle panel

**Estimated:** 3 days

### Phase 3: Toast Notifications

**Files:**
- `apps/papillon/frontend/src/components/approval_toast.rs` (new)
- `apps/papillon/frontend/src/pages/canvas.rs` (spawn toasts on `hitl_pending` change)

**Tasks:**

1. Create toast component with stacking logic
2. Subscribe to `canvas_state.hitl_pending` changes
3. Add quick-approve for zero-disclosure agents
4. Add "VIEW DETAILS" button that opens workflow panel
5. Implement 30s auto-dismiss timeout
6. Style with purple accent + animations

**Estimated:** 1 day

### Phase 4: Ghost Block Enhancement

**Files:**
- `apps/papillon/frontend/src/components/block_renderer/ghost.rs` (enhance existing)
- `apps/papillon/frontend/src/components/skeleton_preview.rs` (new)

**Tasks:**

1. Add skeleton preview generator (block characters)
2. Build type-specific skeletons (FlightReservation, WeatherForecast, etc.)
3. Show multi-agent indicator ("From 3 agents")
4. Display schema.org type icon + property count

**Estimated:** 1 day

### Phase 5: Integration & Polish

**Files:**
- All of the above + CSS styling

**Tasks:**

1. End-to-end test: prompt → curation → approval → execution → render
2. Keyboard navigation audit (all shortcuts work)
3. Dark mode styling pass
4. Animation polish (tab switching, panel slide, toast stack)
5. Error state handling (no agents found, disclosure validation, network failure)
6. Documentation update (user guide, architecture diagrams)

**Estimated:** 2 days

**Total Estimate:** 8 days (1.5 sprint)

## Implementation Details & Existing Patterns

### Code Patterns to Follow

**Component Structure** (from `topbar.rs`):
```rust
#[component]
pub fn ComponentName() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let signal = RwSignal::new(initial_value);
    
    view! {
        <div class="component-class">
            // Leptos view
        </div>
    }
}
```

**Slide Panel Pattern** (`topbar.rs` lines 79-168):
- Backdrop: `<div class=move || if open { "slide-panel-backdrop open" } else { "slide-panel-backdrop" }/>`
- Panel: `<div class=move || if open { "slide-panel open" } else { "slide-panel" }>`
- Backdrop closes panel on click
- CSS transitions already defined in `main.css`

**Canvas List Pattern** (`topbar.rs` lines 84-126):
```rust
<For
    each=canvases
    key=|c| c.id.clone()
    children=move |canvas| {
        let cid = canvas.id.clone();
        view! {
            <div class="panel-canvas-item" class:active=move || is_active(&cid)>
                <div class="panel-canvas-dot" class:active=move || is_active(&cid) />
                <span>{canvas.name}</span>
            </div>
        }
    }
/>
```

**Keyboard Shortcuts** (`topbar.rs` line 135):
- Display: `<span class="panel-kbd">"\u{2318}K"</span>`
- Handle in parent via `on:keydown` event handler

**CSS Design Tokens** (`main.css` lines 49-117):
- Purple: `--purple: #6c5ce7`, `--purple-hover: #7f6ff0`, `--purple-muted: rgba(108, 92, 231, 0.12)`
- Spacing: `--sp-xs: 4px`, `--sp-sm: 8px`, `--sp-md: 16px`, `--sp-lg: 24px`
- Radius: `--r-sm: 4px`, `--r-md: 8px`, `--r-lg: 12px`
- Typography: `--text-ui: 400 13px/1.4 var(--font-body)`, `--text-label: 500 11px/1.2 var(--font-mono)`
- Topbar: `--topbar-height: 36px`

### Existing State & Methods

**Canvas State** (`apps/papillon/frontend/src/state/canvas.rs`):
- `canvases: RwSignal<Vec<Canvas>>` - all saved canvases
- `current_canvas_id: RwSignal<Option<String>>` - active canvas
- `canvas_side: RwSignal<CanvasSide>` - Front (render) / Back (workflow)
- `canvas_messages: RwSignal<Vec<CanvasMessageRecord>>` - chat thread
- `workflow_graph: RwSignal<WorkflowGraph>` - pipeline graph state
- `hitl_pending: RwSignal<Option<HitlRequest>>` - approval gate requests
- `last_event: RwSignal<Option<CanvasEvent>>` - typed event bus
- `new_canvas()` - creates new canvas (used in topbar.rs:130)
- `delete_canvas(&id)` - deletes canvas (used in topbar.rs:117)
- `submit_prompt(text)` - submits prompt to orchestrator

**Approval Flow** (`apps/papillon/src/commands/canvas/approval.rs`):
- `canvas_plan_prompt()` - creates `IntentPlan` with union of `requires_disclosure` from all candidates
- Returns `AgentCandidate` list with per-agent disclosure reqs
- Auto-approves zero-disclosure on-device agents if configured
- Emits `BlockState::AwaitingApproval`

**Workflow Pipeline** (`apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs`):
- `WorkflowSurfaceContext` - graph navigation context
- Node/edge selection already implemented
- Rendered on `CanvasSide::Back`

## UI Agent System (Future Work)

### Declarative Specs (v1.0)

UI agents advertise:

```json
{
  "@type": "pap:TableComponent",
  "accepts": ["schema:FlightReservation[]"],
  "provides": ["sort", "filter", "paginate"],
  "returns": "pap:ComponentSpec"
}
```

Response format:

```json
{
  "@type": "pap:TableComponent",
  "columns": ["price", "departure", "arrival"],
  "sortable": ["price", "departure"],
  "filterable": ["airline"],
  "data": [/* schema:FlightReservation objects */]
}
```

Papillon's `RendererRegistry` interprets the spec using pre-audited component templates. Ships with 10-15 primitives:
- `TableComponent` (sort/filter/paginate)
- `MapComponent` (schema:GeoCoordinates plotting)
- `TimelineComponent` (schema:Event sequences)
- `ComparisonGrid` (side-by-side schema properties)
- `ChartComponent` (bar, line, pie from numeric properties)

**Why:** Maximum safety. Agents control layout logic, client controls rendering. No code execution.

### WASM Components (v1.1+)

For complex visualizations (3D, WebGL, custom interactions), support WASM components via WASI Component Model:

- Agent returns signed WASM module
- Papillon validates signature against agent DID
- Component runs in sandboxed WASI runtime with capability restrictions
- Requires explicit user approval ("This agent wants to run custom code")
- Code signing mandatory; unsigned components rejected

**Security:** Defense in depth. Declarative path for 80% of use cases, WASM for power users who understand the risks.

## Security Considerations

1. **Agent trust levels** - On-device agents pre-approved, marketplace agents require curation
2. **Disclosure minimization** - Only show required properties, grouped by sensitivity
3. **Signature verification** - All `AgentAdvertisement` objects verified against DID
4. **TTL enforcement** - Mandates expire per protocol spec, UI shows countdown
5. **No UI over wire** - Agents return data, never markup (prevents XSS)
6. **WASM sandboxing** - If UI agents run code, use WASI preview2 capability model
7. **Audit trail** - All approvals logged in episode DB for retrospective review

## Testing Strategy

### Unit Tests

- `CanvasTabBar` click handlers, LRU sorting, overflow logic
- `DisclosureForm` field type inference, union property merging
- `ApprovalToast` stacking logic, auto-dismiss timeout

### Integration Tests

- Full flow: prompt → plan → curation → approval → execution → render
- Multi-agent aggregation: 3 agents selected, results compose into Outcome block
- Zero-disclosure shortcut: on-device agent auto-executes without modal
- Error paths: no agents found, disclosure validation failure, network timeout

### E2E Tests (Playwright)

- Tab navigation: create 6 canvases, verify overflow dropdown works
- Agent curation: uncheck Kayak, verify it's not in execution list
- Disclosure form: fill fields, verify values passed to SD-JWT
- Workflow panel: toggle open/close, verify state persists across tab switches

## Accessibility

- **Keyboard navigation:** All actions accessible via shortcuts (no mouse required)
- **Screen reader:** ARIA labels on agent cards, disclosure fields, toast notifications
- **Focus management:** Opening workflow panel moves focus to first interactive element
- **Color contrast:** Purple accents meet WCAG AA on both light/dark backgrounds

## Performance

- **Tab bar:** Renders max 4 tabs, overflow is lazy-loaded on dropdown open
- **Workflow panel:** Slides in with CSS transform (GPU-accelerated), no layout thrash
- **Disclosure form:** Reactive signals, only re-renders changed fields
- **Toast stack:** Max 3 toasts visible, older ones removed from DOM (not just hidden)

## Open Questions

1. **Workflow panel vs flip-side:** Start with panel, keep flip for pipeline graph?
   - **Decision:** Panel for curation, flip for graph visualization (different concerns)

2. **Ghost block for multi-agent:** Show combined skeleton or per-agent skeletons?
   - **Decision:** Combined skeleton. Ghost is aggregated result preview, not agent list.

3. **Disclosure form field types:** How to infer from schema.org property path?
   - **Decision:** Hardcoded mapping for common types (Person.name → text, Event.startDate → date), fallback to text input.

4. **Pre-approval storage:** Where to persist "always trust this agent" decisions?
   - **Decision:** Episode DB with `trusted_agent_dids` table, keyed by principal DID. UI shows "Trust Always" checkbox on approval.

## Success Metrics

- **Tab adoption:** 90%+ of sessions use multiple canvases (validates tab bar value)
- **Workflow panel usage:** 50%+ of approvals use "VIEW DETAILS" (validates progressive disclosure)
- **Agent curation:** 30%+ of intents have multiple agents selected (validates multi-agent UX)
- **Zero-disclosure shortcuts:** 70%+ of on-device agents auto-approve (validates trust model)

## Rollout Plan

1. **Alpha (internal):** Tab bar + workflow panel, dogfood for 1 week
2. **Beta (early users):** Add toast notifications, gather feedback on approval flow
3. **Release:** Ship with all Phase 1-4 features, monitor metrics
4. **Post-release:** UI agents (declarative specs) in v1.1, WASM in v1.2

## References

- PAP Specification: `docs/specification.md` (6-phase handshake, mandate model)
- Knowledge Graph: `graphify-out/GRAPH_REPORT.md` (architecture visualization)
- Agent Advertisement Schema: `crates/pap-marketplace/src/advertisement.rs`
- Existing Approval Flow: `apps/papillon/src/commands/canvas/approval.rs`
- Canvas State: `apps/papillon/frontend/src/state/canvas.rs`

---

**Next Steps:** Review this spec, then invoke `writing-plans` skill to create implementation plan.

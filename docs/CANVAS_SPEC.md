# Canvas Specification: The Agentic Work Surface

**Status**: DRAFT
**Date**: 2026-03-25
**Authors**: Todd Baur, Claude

## 1. Vision

A canvas is not a chat thread, not a notebook, not a flowchart builder. A canvas is **one automation** — a personal workflow that composes federated agents to do something the user always wanted to do but couldn't wire up themselves.

The user describes what they want. The canvas discovers agents that can do it. PAP ensures each agent only sees what it needs to. The output IS the interface.

There is no build mode. There is no use mode. There is no settings page for integrations. There is one surface, one prompt, and the outcome blocks that emerge from it.

OpenClaw and similar tools hand the entire user context to every agent in the chain. Papillion doesn't. That's the product.

---

## 2. Why This Changes How Apps Work

Every generation of software has asked people to adapt to the machine. The canvas inverts that. To understand why, look at what's broken in each layer of how people use software today.

### 2.1 The App-Centric World (what we have)

You go to Gmail for email. You go to Google Calendar for your schedule. You go to Expedia for flights. You go to Mint for your budget. Each app owns a slice of your life. Each has its own interface, its own login, its own data silo. **You are the integration layer.** You copy a confirmation number from email, paste it into a spreadsheet, check a date on the calendar, then go back to the booking site. Your brain is the bus that shuttles context between applications that refuse to talk to each other.

The result: people spend their time navigating between apps instead of getting things done. The information is all there — it's just trapped behind 30 different logins.

### 2.2 The Integration Layer (Zapier, Make, IFTTT)

These tools tried to fix the silo problem. Connect App A to App B. When a new email arrives, create a task in Todoist. When a deal closes in Salesforce, post to Slack.

But they moved the configuration problem, they didn't solve it. You still set up OAuth flows. You still map fields between APIs. You still debug broken webhooks when a provider changes their schema. The integration tool becomes another app you have to learn. And the integration tool sees everything — your email content, your calendar events, your CRM data — with no partitioning. You granted it full access because that's the only option.

Configuration is the end user's problem. Privacy is nobody's problem.

### 2.3 The AI Assistant Layer (ChatGPT, Claude Desktop, OpenClaw)

AI assistants are the latest attempt. Talk to one agent that has access to everything. "Read my email and summarize it." "Check my calendar and find a time." The natural language interface is a genuine step forward.

But the privacy model is a genuine step backward. The assistant sees your email, your calendar, your files, your browsing history — all of it, all the time, with no partitioning. You trade your entire context for convenience. OpenClaw connects 50 agents to your personal data and every agent sees the same unscoped context. There is no mandate. There is no selective disclosure. There is no receipt proving what was shared.

This is not a minor concern. It is corrosive to the internet. When every agent can see everything about every user, the incentive structure rewards data hoarding, not data minimization. The more context an agent accumulates, the more "useful" it appears — and the more vulnerable the user becomes.

### 2.4 What the Canvas Changes

The Papillion canvas doesn't iterate on any of these. It replaces the assumptions underneath them.

**Configuration disappears.** You don't set up integrations. You don't authenticate with services. You don't map fields between APIs. You describe what you want. The federated agent network discovers agents that can do it. Agents advertise their capabilities via Schema.org vocabularies. The orchestrator matches your intent to available capabilities. The user never sees a settings page for connecting services — because there isn't one. Agent capability advertisements replace API keys and OAuth flows.

**Privacy becomes additive, not subtractive.** Today's model: grant full access to everything, then hope the service only uses what it needs. The canvas model: start from zero disclosure. Each agent gets a mandate scoped to exactly what it needs for exactly this task, with a TTL that expires. A flight search agent sees your travel dates and destination. It does not see your email. It does not see your budget. It does not see your name. And you can prove this — co-signed receipts contain property references, never values. The privacy guarantee is cryptographic, not a privacy policy you can't read.

**The interface IS the automation.** There is no "build" screen and "use" screen. No workflow editor that looks different from the result. You prompt, the canvas shows you what will happen (ghost blocks), you approve, the outcome appears. Then you reshape the outcome by talking to it. The same surface that displays your morning briefing is the surface where you built it by typing "every morning, summarize my email and check the weather." Draft and live are the same canvas at different lifecycle stages.

**Apps dissolve into agents.** Instead of going to Gmail, an email agent brings relevant messages to your canvas. Instead of going to a weather site, a weather agent contributes to your briefing. The app boundary — the idea that a company's product is a destination you visit — dissolves. What remains is capability: an agent can search, an agent can check, an agent can book. The canvas composes capabilities. The user never thinks about which app is behind which capability.

**The user is the root of trust.** Not a platform. Not a cloud provider. Not a company. The user's cryptographic identity (DID) anchors every interaction. Mandates flow from the user. Receipts are co-signed by the user. The memex — the learning layer — lives on the user's device, in their SQLite database, never uploaded. The orchestrator improves by learning the user's preferences locally. No training data leaves the machine.

### 2.5 The Paradigm in One Sentence

Today, people go to apps and give them everything. With the canvas, agents come to people and get only what they need.

---

## 3. Core Model: Outcome Blocks

The canvas does not show agent plumbing by default. When a user prompts a multi-step workflow, the orchestrator runs the agents, collects their responses, and synthesizes a single **outcome block** that represents the user's desired result.

Individual agent interactions are the **provenance layer** — expandable underneath the outcome block. They show which agents contributed, what each agent saw (mandate scope), and cryptographic receipts proving the interaction.

### 3.1 Two-Layer Model

| Layer | What the user sees | When visible |
|-------|-------------------|--------------|
| **Surface** | Outcome blocks — synthesized answers to what the user asked | Always |
| **Provenance** | Agent blocks — individual handshake results, mandate scopes, receipts | On expand ("N agents contributed") |

### 3.2 Outcome Block Anatomy

```
+---------------------------------------------------+
|  [Outcome Title]                        [status]   |
|                                                    |
|  [Synthesized content — formatted, readable,       |
|   answering the user's actual question]            |
|                                                    |
|  > N agents contributed · [privacy posture]        |
+---------------------------------------------------+
```

**Title**: Auto-generated from the user's prompt (e.g., "Tokyo Trip Options", "Morning Briefing · Mar 25").

**Content**: Produced by the on-device LLM (Candle) from the collected agent responses. Never leaves the device. Rendered as text using the existing typed renderer system where applicable.

**Provenance footer**: Expandable. Shows each agent block with:
- Agent name and action type
- Mandate scope badge (what this agent saw / did not see)
- Timing and quality metrics
- Co-signed receipt link

### 3.3 Reshaping Outcomes

The user reshapes the **outcome**, not individual agents. Clicking the outcome block opens a re-prompt:

- "Only direct flights under $1000" — orchestrator determines which agent to re-run
- "Add weather for each destination" — orchestrator adds an agent step and re-synthesizes
- "Less detail, just show me the cheapest option" — re-synthesis only, no agent re-run

The orchestrator decides whether a reshape requires re-running agents (scope change) or just re-synthesizing (presentation change).

---

## 4. Canvas Lifecycle

### 4.1 States

| State | Meaning | Stored |
|-------|---------|--------|
| **Draft** | User is building — prompting, reshaping, exploring | In-memory (optionally persisted) |
| **Armed** | Automation defined, trigger attached, waiting | SQLite `canvases` table |
| **Live** | Running on trigger, producing outcome blocks | SQLite, scheduler active |
| **Paused** | Stopped after failure or user action, retains history | SQLite, scheduler skips |

### 4.2 State Transitions

```
[New Canvas] --> Draft
Draft --> Armed          (user attaches trigger and arms)
Armed --> Live           (user activates)
Live --> Paused          (user pauses OR 3 consecutive failures)
Paused --> Live          (user resumes)
Armed --> Draft          (user disarms to edit)
Live --> Draft           (user disarms to edit — creates new version)
```

### 4.3 Canvas as Timeline

A live canvas produces one outcome block per run. The canvas becomes a **timeline of outcomes**:

```
Today
+-------------------------------------------+
| Morning Briefing · Mar 25                  |
| ...                                        |
+-------------------------------------------+

Yesterday
+-------------------------------------------+
| Morning Briefing · Mar 24                  |
| ...                                        |
+-------------------------------------------+
```

Scroll up to see previous runs. Each outcome block retains its provenance layer.

---

## 5. Prompt Decomposition

### 5.1 Intent Detection

When the user submits a prompt, the system detects whether it's single-step or multi-step before creating any blocks.

**Single-step** (current behavior, unchanged):
- "what's the weather" — one agent, one block, immediate execution

**Multi-step** (new: plan mode):
- Language cues trigger decomposition:
  - Sequential: "then", "after that", "next", "once you have"
  - Parallel: "and", "also", "at the same time"
  - Conditional: "if", "only when", "unless"
  - Temporal/trigger: "every", "whenever", "when", "daily"

**The user doesn't select a mode.** The system infers it from language. Single-intent prompts bypass planning entirely.

### 5.2 Ghost Blocks

Multi-step prompts produce **ghost blocks** — a preview of what will happen before it happens.

```rust
pub enum BlockState {
    Ghost {
        agent_name: String,
        action_type: String,
        disclosure_preview: Vec<String>,
        returns_preview: Vec<String>,
    },
    Resolving { phase: u8, phase_label: String },
    Resolved,
    Failed { phase: u8, reason: String },
    Outcome {
        provenance_block_ids: Vec<String>,
        expanded: bool,
    },
}
```

Ghost blocks render as dashed outlines (semi-transparent, muted wing spectrum colors). They show:
- Which agent will handle this step
- What it needs to see (mandate scope preview)
- What it will produce
- How it connects to adjacent ghost blocks

### 5.3 Ghost Outcome Block

Above the ghost agent blocks, a single **ghost outcome block** shows the anticipated result shape:

```
+ - - - - - - - - - - - - - - - - - - - - -+
| Tokyo Trip Options                        |
|                                           |
| Will search flights (3 carriers), hotels  |
| (near arrival airport), then compare by   |
| total cost                                |
|                                           |
| 3 agents · Each sees only what it needs   |
|                                           |
| [Run]   [Adjust: "only direct flights"]   |
+ - - - - - - - - - - - - - - - - - - - - -+
```

### 5.4 Plan Refinement

All refinement happens through prompts, not UI controls:

- **Click the ghost outcome**: re-prompt reshapes the whole plan
- **Click between ghost agent blocks**: insert a step ("also check if I've been there before")
- **Click a ghost agent block**: reshape that step ("only search Marriott properties")

A commit bar appears below the ghost plan:

```
+---------------------------------------------------+
| [Run this plan]    [Adjust]    [Cancel]            |
+---------------------------------------------------+
```

"Run this plan" transitions ghost blocks to Resolving, executes the pipeline, and produces an outcome block.

---

## 6. Privacy as UX

### 6.1 The Provenance Footer

Every outcome block shows:

```
> 3 agents contributed · Guarded privacy
```

This single line is PAP's differentiator. Expanding it reveals the full provenance:

```
  +-- Flight Search ---------------------------------+
  | Searched 4 carriers via SearchAction             |
  | Saw: travel dates, origin, destination           |
  | Did not see: email, budget, name, payment        |
  | Receipt: co-signed, session did:key:z6Mk...      |
  +--------------------------------------------------+
  +-- Hotel Search ----------------------------------+
  | Searched 12 properties via SearchAction          |
  | Saw: destination city (from flight result only)  |
  | Did not see: travel dates, budget, name          |
  | Receipt: co-signed, session did:key:z6Qr...      |
  +--------------------------------------------------+
  +-- On-Device Synthesis ---------------------------+
  | Composed by local LLM (never left device)        |
  | Saw: both agent results (local only)             |
  | No external receipt (on-device)                  |
  +--------------------------------------------------+
```

### 6.2 Narrowing Scope

Inside the provenance view, each agent block has a "Narrow scope" affordance. Clicking it opens a re-prompt: "What should this agent NOT see?" The user types constraints in natural language and the mandate tightens. The orchestrator re-runs that agent with the narrower mandate and re-synthesizes the outcome.

### 6.3 Privacy Posture

Each canvas has a privacy posture (seeded from onboarding, overridable per canvas):

| Posture | Behavior |
|---------|----------|
| **Guarded** | Minimum disclosure always. Short mandate TTLs. Never share across agents unless explicitly bridged. Default. |
| **Balanced** | Share what's needed for the task. TTL calibrated by action type. |
| **Open** | Broader disclosure for richer results. User acknowledges tradeoff. |

The posture is visible in the trigger bar and provenance footer.

---

## 7. Layout Engine

### 7.1 Derived Layout

Users never drag blocks. The DAG structure (edges between agent blocks in the provenance layer) determines spatial position. The layout algorithm computes positions from topological depth and concurrency.

### 7.2 Surface Layer (Outcome Blocks)

Outcome blocks render as a **vertical timeline** — one per prompt (draft mode) or one per run (live mode). This is a linear list, same as today but with richer block content.

### 7.3 Provenance Layer (Agent Blocks)

When expanded, agent blocks render with topological layout:

- **Linear chains**: Single column, sequential rows (identical to current behavior)
- **Branches**: Fan out horizontally at the branch point
- **Merges**: Converge back to single column

```
          +------------+
          | Search     |
          | flights    |
          +-----+------+
          |            |
    +-----v----+ +----v-----+
    | Check    | | Check    |
    | hotels   | | car      |
    +-----+----+ +----+-----+
          |            |
          +-----+------+
          |            |
    +-----v------------v----+
    | Synthesize outcome     |
    +------------------------+
```

Connection lines are SVG paths using wing spectrum colors:
- `--teal` for completed connections
- `--gold` for in-progress
- `--text-3` for ghost connections

### 7.4 Zoom Levels

| Level | What's visible | Trigger |
|-------|---------------|---------|
| **Close** (default) | Full outcome block content, provenance expandable | Default |
| **Medium** | Outcome titles + status, provenance as compact list | Trackpad pinch out |
| **Far** | Dots and lines — shape of the automation | Further pinch out |

Zoom is CSS-driven:

```css
.canvas-area[data-zoom="close"] .outcome-content { display: block; }
.canvas-area[data-zoom="medium"] .outcome-content { display: none; }
.canvas-area[data-zoom="medium"] .outcome-summary { display: block; }
.canvas-area[data-zoom="far"] .outcome-block {
    width: 12px; height: 12px;
    border-radius: 50%;
}
```

---

## 8. Onboarding

### 8.1 Purpose

The memex (SQLite episode store) starts empty. Agent profiles have no EMA scores. The orchestrator guesses during cold-start. Onboarding seeds the memex so the system is useful from minute one.

### 8.2 Three Screens

**Screen 1: "What matters to you?"**

Conversational prompt that maps to Schema.org action affinities:
- "Stay on top of my email" -> high affinity for ReadAction, email agents
- "Track prices on things" -> CheckAction, comparison/monitor agents
- "Always prepping for meetings" -> SearchAction + ReadAction, calendar/email/research

Stored as: `setting: user.intent_affinities`

Biases `score_agent()` during cold-start: affinity-matched agents get preferred baseline scores.

**Screen 2: "How careful should we be?"**

Privacy posture selection: Guarded (default) / Balanced / Open. Visual, three distinct options.

Stored as: `setting: user.privacy_posture`

Feeds into mandate calibration — posture multiplier on disclosure scope breadth and mandate TTL.

**Screen 3: "Here's your first canvas"**

Based on Screen 1 answers, present 2-3 starter canvas templates pre-wired and ready to run:
- "Morning Briefing" — news + weather + calendar summary
- "Price Watch" — search + threshold check, armed with schedule
- "Meeting Prep" — calendar pull + attendee research + email threads

User picks one, it hydrates into ghost blocks, they hit Run. First outcome block appears. First episodes record. Cold-start cycle broken in under 2 minutes.

### 8.3 First Run as Onboarding

The starter canvas IS the first pipeline run. No tutorial, no walkthrough, no empty canvas. The user sees Papillion produce a real result, with privacy guarantees visible, within the first interaction.

"Want this every morning?" -> Arms the canvas with schedule trigger -> Now it's live. The memex learns. The orchestrator improves. The person has a working automation.

---

## 9. Trigger System

### 9.1 TriggerConfig

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TriggerConfig {
    Manual,
    Schedule {
        interval_secs: u64,
        anchor_time: Option<String>,    // "07:00" HH:MM
        days_of_week: Option<Vec<u8>>,  // 1=Mon..7=Sun
    },
    Event {
        poll_interval_secs: u64,
        filter: String,
    },
    Canvas {
        upstream_canvas_id: String,
    },
}
```

### 9.2 Natural Language Schedule Parsing

User-facing schedules are natural language. Parsing follows the same pattern as `detect_intent()`:

- "every morning at 7" -> Schedule { interval: 86400, anchor: "07:00" }
- "twice a day" -> Schedule { interval: 43200 }
- "on weekdays" -> Schedule { interval: 86400, days: [1,2,3,4,5] }
- "when I get a new email" -> Event { poll: 300, filter: "new email" }
- Ambiguous phrases fall back to on-device LLM for structured extraction

Schedules are always displayed in natural language, never cron.

### 9.3 Desktop Catch-Up Semantics

Papillion is a desktop app. Laptops sleep. The scheduler does not use cron. It uses interval-based evaluation with catch-up:

- If anchor time has passed and interval elapsed since last run: **fire on next tick**
- **One catch-up run maximum** — don't queue missed intervals
- The "Morning Briefing" runs at 8:01am because that's when the laptop opened. This is correct behavior.

### 9.4 Event Triggers

For event triggers, the first pipeline node IS the event detector. The scheduler polls it on interval. If the event-source agent returns empty results (no new email, no price change), the pipeline **short-circuits** — recorded as "skipped", no downstream execution.

### 9.5 Canvas Chaining

A canvas can trigger when an upstream canvas completes. When canvas A finishes a run, the scheduler immediately checks if any canvas depends on A and queues them for execution.

---

## 10. Scheduler Architecture

### 10.1 Placement

The scheduler is a background tokio loop spawned alongside the discovery loop in `start_federation_server_async`. It shares `Arc<AppState>` with the federation server.

### 10.2 Tick Cycle

Every 60 seconds:
1. Query all live canvases (partial index: `WHERE state = 'live'`)
2. Budget check: max 3 concurrent pipeline executions
3. Evaluate each canvas trigger: is it due?
4. Execute due canvases (oldest-first priority)
5. Record runs, emit Tauri events, update memex

### 10.3 Pipeline Execution

The core pipeline executor is extracted from the Tauri command into a shared function callable from both the frontend (via Tauri IPC) and the scheduler (direct call):

```rust
pub(crate) async fn execute_pipeline(
    app: &AppHandle,
    state: &AppState,
    pipeline: &PipelineInfo,
    initial_query: &str,
) -> Result<PipelineExecutionResult, PapillionError>
```

### 10.4 Guardrails

- **Run lock**: One execution per canvas at a time
- **Failure backoff**: 3 consecutive failures -> auto-pause, notify user
- **Budget cap**: Max 3 concurrent pipeline executions (configurable)
- **Quiet hours**: Optional per-canvas time window where triggers don't fire

---

## 11. Canvas Persistence

### 11.1 Schema

```sql
CREATE TABLE IF NOT EXISTS canvases (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL,
    pipeline_json         TEXT NOT NULL,
    trigger_config_json   TEXT NOT NULL,
    privacy_posture       TEXT NOT NULL DEFAULT 'guarded'
                          CHECK(privacy_posture IN ('guarded','balanced','open')),
    state                 TEXT NOT NULL DEFAULT 'draft'
                          CHECK(state IN ('draft','armed','live','paused')),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    last_run_at           TEXT,
    run_count             INTEGER NOT NULL DEFAULT 0,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_canvases_state ON canvases(state);
CREATE INDEX IF NOT EXISTS idx_canvases_live ON canvases(state, last_run_at)
    WHERE state = 'live';

CREATE TABLE IF NOT EXISTS canvas_runs (
    id              TEXT PRIMARY KEY,
    canvas_id       TEXT NOT NULL REFERENCES canvases(id) ON DELETE CASCADE,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'running'
                    CHECK(status IN ('running','completed','failed','partial','skipped')),
    result_json     TEXT,
    episode_ids     TEXT NOT NULL DEFAULT '[]',
    trigger_source  TEXT NOT NULL DEFAULT 'manual'
);

CREATE INDEX IF NOT EXISTS idx_canvas_runs_canvas ON canvas_runs(canvas_id, started_at);
CREATE INDEX IF NOT EXISTS idx_canvas_runs_running ON canvas_runs(canvas_id, status)
    WHERE status = 'running';
```

### 11.2 DatabaseOps Extensions

```rust
// Canvas CRUD
fn insert_canvas(&self, canvas: &CanvasInfo) -> Result<(), DbError>;
fn update_canvas(&self, canvas: &CanvasInfo) -> Result<(), DbError>;
fn update_canvas_state(&self, id: &str, state: &str) -> Result<(), DbError>;
fn get_canvas(&self, id: &str) -> Result<Option<CanvasInfo>, DbError>;
fn list_canvases(&self, state_filter: Option<&str>) -> Result<Vec<CanvasInfo>, DbError>;
fn delete_canvas(&self, id: &str) -> Result<(), DbError>;

// Scheduler queries
fn list_live_canvases(&self) -> Result<Vec<CanvasInfo>, DbError>;
fn has_running_execution(&self, canvas_id: &str) -> Result<bool, DbError>;
fn latest_completed_run_time(&self, canvas_id: &str) -> Result<Option<String>, DbError>;
fn list_canvases_triggered_by(&self, canvas_id: &str) -> Result<Vec<CanvasInfo>, DbError>;

// Run management
fn record_canvas_run_start(&self, canvas_id: &str, run: &CanvasRun) -> Result<(), DbError>;
fn record_canvas_run_complete(&self, run_id: &str, status: &str, result: Option<&str>, episodes: &[String]) -> Result<(), DbError>;
fn list_canvas_runs(&self, canvas_id: &str, limit: usize) -> Result<Vec<CanvasRun>, DbError>;
```

---

## 12. Synthesizer Node

### 12.1 Purpose

The synthesizer is the final node in every multi-step pipeline. It takes all upstream agent results and the user's original prompt, runs the on-device LLM, and produces the outcome block content.

### 12.2 Pipeline Node Type

```rust
pub enum NodeType {
    Agent,
    Synthesizer {
        outcome_prompt: String,
    },
}
```

### 12.3 Properties

- Runs on-device only (Candle/TinyLlama). Never an external agent.
- No mandate, no receipt, no external handshake.
- Receives all upstream JSON-LD results as context.
- Produces structured content matching the user's desired outcome shape.
- If the on-device LLM is not configured, falls back to structured JSON composition (merge upstream results into a single JSON-LD object).

---

## 13. UI Component Architecture

### 13.1 New Components

| Component | Purpose |
|-----------|---------|
| `outcome_block.rs` | Renders synthesized outcome with expandable provenance |
| `ghost_outcome.rs` | Renders ghost plan preview with commit/adjust/cancel |
| `ghost_block.rs` | Renders individual ghost agent block (dashed outline) |
| `provenance_layer.rs` | Expandable agent block list with scope badges and receipts |
| `scope_badge.rs` | Mandate scope visualization ("Sees: X / Does not see: Y") |
| `connection_lines.rs` | SVG edge rendering for provenance layer |
| `trigger_bar.rs` | Schedule/trigger configuration and status |
| `plan_bar.rs` | Commit/adjust/cancel controls for ghost plans |
| `canvas_sidebar.rs` | Canvas list grouped by state with status indicators |
| `inter_block_prompt.rs` | Prompt insertion point between ghost blocks |
| `canvas_layout.rs` | Topological position computation for provenance view |

### 13.2 Modified Components

| Component | Change |
|-----------|--------|
| `canvas.rs` (page) | Add zoom controls, sidebar toggle, trigger bar |
| `canvas.rs` (state) | Ghost blocks, plan commit, outcome synthesis |
| `block_renderer/mod.rs` | Ghost and Outcome block state rendering |

### 13.3 Unchanged Components

- Block renderer dispatch (blessed + generic + templates)
- All existing typed renderers (Flight, Hotel, Search, Answer)
- Phase dots component
- Receipt footer component

---

## 14. Tauri Commands

### 14.1 New Commands

```rust
// Canvas lifecycle
canvas_create(name, pipeline) -> CanvasInfo
canvas_arm(canvas_id, trigger_config) -> ()
canvas_activate(canvas_id) -> ()
canvas_pause(canvas_id) -> ()
canvas_resume(canvas_id) -> ()
canvas_list(state_filter?) -> Vec<CanvasInfo>
canvas_get_runs(canvas_id, limit) -> Vec<CanvasRun>

// Plan decomposition
canvas_decompose(prompt) -> Vec<GhostBlock>
canvas_commit_plan(canvas_id) -> ()

// Synthesis
canvas_synthesize(prompt, agent_results) -> OutcomeContent
```

### 14.2 New Events

```rust
// Scheduler notifications
"canvas_run_started" -> { canvas_id, run_id }
"canvas_run_completed" -> { canvas_id, run_id, status, steps }
"canvas_auto_paused" -> { canvas_id, canvas_name, reason }
```

---

## 15. Design System Integration

All new components use existing design tokens from DESIGN.md:

- **Ghost blocks**: `--border-subtle` dashed border, `--bg-1` fill, `--text-3` content
- **Outcome blocks**: `--bg-2` fill, `--border` solid, `--text-1` content
- **Provenance expanded**: `--bg-1` fill, indented under outcome
- **Scope badges**: `--teal` for "saw", `--coral` for "did not see"
- **Connection lines**: SVG stroke using `--teal`/`--gold`/`--text-3`
- **Trigger bar**: `--bg-2` fill, `--purple` for action buttons
- **Ghost outcome**: dashed `--purple-muted` border
- **Status dots**: `--teal` (resolved), `--gold` (resolving), `--coral` (failed)

Typography:
- Outcome title: H2 (Satoshi 22px/700)
- Outcome content: Body (DM Sans 15px/400)
- Provenance agent name: UI (DM Sans 13px/400)
- Scope badge: Label (JetBrains Mono 11px/500, uppercase)
- DIDs in provenance: Mono (JetBrains Mono 13px/400)

---

## 16. Implementation Phases

### Phase 1: Outcome Block + Provenance Layer
- Add `Outcome` and `Ghost` to `BlockState`
- Build `outcome_block.rs` and `provenance_layer.rs` components
- Build `scope_badge.rs`
- Wire synthesizer node into pipeline executor
- Single-prompt outcome blocks working end-to-end

### Phase 2: Plan Mode (Ghost Blocks)
- Implement `canvas_decompose` backend command (intent -> ghost block plan)
- Build `ghost_outcome.rs`, `ghost_block.rs`, `plan_bar.rs`
- Build `inter_block_prompt.rs` for plan refinement
- Plan commit -> pipeline execution -> outcome block

### Phase 3: Canvas Persistence + Sidebar
- Add `canvases` and `canvas_runs` tables
- Implement `DatabaseOps` extensions
- Build `canvas_sidebar.rs`
- Canvas CRUD Tauri commands
- Canvas state transitions

### Phase 4: Trigger System + Scheduler
- Implement `TriggerConfig` and NL schedule parsing
- Build `trigger_bar.rs`
- Implement `scheduler.rs` background loop
- Refactor `run_pipeline` into shared `execute_pipeline`
- Event trigger short-circuiting
- Canvas chaining
- Auto-pause on failure

### Phase 5: Onboarding
- Implement three onboarding screens
- Build starter canvas templates
- Wire affinity and posture settings into `score_agent`
- First-run flow: onboarding -> starter canvas -> first outcome

### Phase 6: Layout + Zoom
- Implement topological layout engine for provenance layer
- Build `connection_lines.rs` (SVG edges)
- Implement zoom levels (close/medium/far)
- CSS-driven zoom transitions

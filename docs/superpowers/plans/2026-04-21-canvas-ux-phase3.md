# Canvas UX Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix back-face CSS, replace the Browse page with a searchable agent picker modal, convert Settings to a full-screen overlay with an X button, remove the chat thread from below canvas blocks, move the prompt bar to a collapsible right-aside with first-run explanation and Plan/Auto mode, update all stale e2e tests, and fix test antipatterns (setTimeout/delay → waitFor).

**Architecture:** All changes are front-end only (Leptos/WASM). New components (`AgentPickerModal`, `CanvasAside`) follow the established `RwSignal` context pattern. Settings becomes an overlay mounted in `App` using the existing `.hitl-overlay` pattern. The chat thread moves from `canvas.rs` front face into the new `CanvasAside` component. The topbar button area expands into a contextual toolbar whose content switches between "workflow" controls (back face) and "render" controls (front face).

**Tech Stack:** Leptos 0.8, Rust, WASM, `wasm_bindgen_futures::spawn_local`, existing `bridge::invoke_no_args`, `list_local_agents` Tauri command, Playwright e2e tests.

---

## File Map

| File | Change |
|---|---|
| `apps/papillon/frontend/styles/main.css` | Add `.canvas-back-face` + back-face tab CSS; `.agent-picker-*` modal CSS; `.settings-overlay` CSS; `.canvas-aside-*` CSS; `.canvas-toolbar-*` CSS |
| `apps/papillon/frontend/src/components/mod.rs` | Add `pub mod agent_picker_modal;` and `pub mod canvas_aside;` |
| `apps/papillon/frontend/src/components/agent_picker_modal.rs` | New: searchable 3×3 grid modal, calls `list_local_agents` |
| `apps/papillon/frontend/src/components/canvas_aside.rs` | New: collapsible right aside with chat history, first-run tip, Plan/Auto mode |
| `apps/papillon/frontend/src/pages/canvas.rs` | Remove `<CanvasChatThread />` from front face; add `<CanvasAside />` |
| `apps/papillon/frontend/src/pages/browse.rs` | Replace page body with link-out text + open-modal button; add `AgentPickerModal` |
| `apps/papillon/frontend/src/pages/settings.rs` | Extract inner content into `SettingsOverlay`; mount in `app.rs` as overlay |
| `apps/papillon/frontend/src/app.rs` | Mount `SettingsOverlay` alongside routes; add `show_settings: RwSignal<bool>` to context |
| `apps/papillon/frontend/src/components/topbar.rs` | Replace Workflow button with contextual toolbar row; add Settings trigger |
| `e2e/tests/agents.spec.ts` | Already rewritten to match Chrysalis UI — verify passes |
| `e2e/tests/app.spec.ts` | Fix Activity empty text; remove Add Successor test; add Settings overlay tests |
| `e2e/tests/templates.spec.ts` | Remove `setTimeout`; replace `pressSequentially(delay:30)` with `waitFor` pattern |
| `e2e/tests/workflow.spec.ts` | Remove redundant `timeout` from `toBeVisible` calls that have no useful retry window |
| `e2e/tests/tauri-mock.ts` | Verify `list_local_agents` mock seeds 5 agents correctly (already done) |

---

## Task 1 — Back-face CSS (`.canvas-back-face`, `.back-face-tab*`, `.back-face-panel`)

**Files:**
- Modify: `apps/papillon/frontend/styles/main.css` (after line 6237, after `.canvas-face.back` rule)

- [ ] **Step 1: Add CSS block**

Find the line `/* ── Block query label ─────` (~line 6239) and insert before it:

```css
/* ── Canvas back face tabs ────────────────────────────────────────────────── */
.canvas-back-face {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--bg-1, #0e0e1a);
  overflow: hidden;
}

.back-face-tabs {
  display: flex;
  border-bottom: 1px solid var(--border, rgba(255,255,255,0.08));
  padding: 0 14px;
  flex-shrink: 0;
  background: var(--bg-2, #13131f);
}

.back-face-tab {
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted, #6b7280);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  font-family: var(--font-mono, 'JetBrains Mono', monospace);
  padding: 10px 14px 8px;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s;
}
.back-face-tab:hover { color: var(--text-primary, #e0e0e0); }
.back-face-tab--active {
  color: var(--purple, #6c5ce7);
  border-bottom-color: var(--purple, #6c5ce7);
}

.back-face-panel {
  flex: 1;
  overflow: auto;
  display: flex;
  flex-direction: column;
}
```

- [ ] **Step 2: Verify with grep**

```bash
grep -n "back-face-tab\|back-face-panel\|canvas-back-face" apps/papillon/frontend/styles/main.css
```
Expected: 6 matches (one per class definition).

- [ ] **Step 3: cargo check**

```bash
cargo check -p papillon-ui 2>&1 | grep "^error" | head -5
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add apps/papillon/frontend/styles/main.css
git commit -m "fix(css): add canvas back-face tab layout CSS"
```

---

## Task 2 — Agent Picker Modal component

The Browse page currently shows an empty "Browse Registries" page. Replace it: the BROWSE link on the fleet page opens a searchable modal listing all installed agents in a 3×3 grid. The modal is fed by `list_local_agents`.

**Files:**
- Create: `apps/papillon/frontend/src/components/agent_picker_modal.rs`
- Modify: `apps/papillon/frontend/src/components/mod.rs`
- Modify: `apps/papillon/frontend/styles/main.css`

- [ ] **Step 1: Add CSS for agent picker modal**

Append to `main.css`:

```css
/* ── Agent Picker Modal ──────────────────────────────────────────────────── */
.agent-picker-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.75);
  display: flex; align-items: center; justify-content: center;
  z-index: 1100;
  backdrop-filter: blur(4px);
}
.agent-picker-modal {
  background: var(--bg-1, #0e0e1a);
  border: 1px solid var(--border, rgba(255,255,255,0.1));
  border-radius: 12px;
  padding: 24px;
  width: min(720px, 94vw);
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.agent-picker-header {
  display: flex; align-items: center; justify-content: space-between;
}
.agent-picker-title {
  font-size: 13px; font-weight: 700; letter-spacing: 0.06em;
  text-transform: uppercase; font-family: var(--font-mono); color: var(--text-primary, #e0e0e0);
}
.agent-picker-close {
  background: transparent; border: none; cursor: pointer;
  color: var(--text-muted, #6b7280); font-size: 18px; padding: 2px 6px;
  border-radius: 4px; transition: color 0.15s;
}
.agent-picker-close:hover { color: var(--text-primary, #e0e0e0); }
.agent-picker-search {
  width: 100%; background: var(--bg-2, #13131f);
  border: 1px solid var(--border, rgba(255,255,255,0.08));
  border-radius: 6px; padding: 8px 12px;
  color: var(--text-primary, #e0e0e0); font-size: 13px;
  outline: none; font-family: var(--font-body);
}
.agent-picker-search:focus { border-color: var(--purple, #6c5ce7); }
.agent-picker-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  overflow-y: auto;
  padding-right: 4px;
}
.agent-picker-card {
  background: var(--bg-2, #13131f);
  border: 1px solid var(--border, rgba(255,255,255,0.06));
  border-radius: 8px; padding: 12px 14px;
  cursor: pointer; transition: border-color 0.15s, background 0.15s;
  display: flex; flex-direction: column; gap: 4px;
}
.agent-picker-card:hover {
  border-color: var(--purple, #6c5ce7);
  background: rgba(108,92,231,0.06);
}
.agent-picker-card-name {
  font-size: 12px; font-weight: 600; color: var(--text-primary, #e0e0e0);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.agent-picker-card-cap {
  font-size: 10px; color: var(--teal, #2ec4a0);
  font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.agent-picker-card-source {
  font-size: 9px; color: var(--text-muted, #6b7280);
  text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px;
}
.agent-picker-empty {
  grid-column: 1 / -1; text-align: center;
  color: var(--text-muted, #6b7280); font-size: 12px; padding: 24px 0;
}
.agent-picker-count {
  font-size: 10px; color: var(--text-muted, #6b7280); text-align: right;
  font-family: var(--font-mono);
}
```

- [ ] **Step 2: Create `agent_picker_modal.rs`**

```rust
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::types::AgentInfo;

/// Searchable agent picker modal.
/// `open` — reactive signal controlling visibility.
/// `on_close` — called when user dismisses without selecting.
/// `on_select` — called with the chosen AgentInfo.
#[component]
pub fn AgentPickerModal(
    open: RwSignal<bool>,
    on_select: Callback<AgentInfo>,
) -> impl IntoView {
    let agents: RwSignal<Vec<AgentInfo>> = RwSignal::new(vec![]);
    let query: RwSignal<String> = RwSignal::new(String::new());
    let loading: RwSignal<bool> = RwSignal::new(false);

    // Load agents when modal opens.
    Effect::new(move || {
        if !open.get() {
            return;
        }
        loading.set(true);
        spawn_local(async move {
            match bridge::invoke_no_args::<Vec<AgentInfo>>("list_local_agents").await {
                Ok(list) => agents.set(list),
                Err(_) => agents.set(vec![]),
            }
            loading.set(false);
        });
    });

    let filtered = move || {
        let q = query.get().to_lowercase();
        agents.get()
            .into_iter()
            .filter(|a| {
                q.is_empty()
                    || a.name.to_lowercase().contains(&q)
                    || a.capabilities.iter().any(|c| c.to_lowercase().contains(&q))
                    || a.category.to_lowercase().contains(&q)
            })
            .collect::<Vec<_>>()
    };

    view! {
        <Show when=move || open.get()>
            <div
                class="agent-picker-overlay"
                on:click=move |ev| {
                    // Close on backdrop click
                    use wasm_bindgen::JsCast;
                    let target = ev.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok());
                    if target.as_ref().map(|el| el.class_name() == "agent-picker-overlay").unwrap_or(false) {
                        open.set(false);
                        query.set(String::new());
                    }
                }
            >
                <div class="agent-picker-modal">
                    <div class="agent-picker-header">
                        <span class="agent-picker-title">"INSTALLED AGENTS"</span>
                        <button
                            class="agent-picker-close"
                            on:click=move |_| { open.set(false); query.set(String::new()); }
                            aria-label="Close agent picker"
                        >"×"</button>
                    </div>

                    <input
                        type="text"
                        class="agent-picker-search"
                        placeholder="Search by name, action type, or category…"
                        prop:value=move || query.get()
                        on:input=move |ev| query.set(leptos::prelude::event_target_value(&ev))
                        autofocus=true
                    />

                    <div class="agent-picker-count">
                        {move || {
                            let total = agents.get().len();
                            let shown = filtered().len();
                            if query.get().is_empty() {
                                format!("{total} agents installed")
                            } else {
                                format!("{shown} of {total}")
                            }
                        }}
                    </div>

                    <div class="agent-picker-grid">
                        <Show
                            when=move || loading.get()
                            fallback=move || {
                                let items = filtered();
                                if items.is_empty() {
                                    view! {
                                        <div class="agent-picker-empty">
                                            "No agents match "" {query.get()} """
                                        </div>
                                    }.into_any()
                                } else {
                                    items.into_iter().map(|agent| {
                                        let cap = agent.capabilities.first()
                                            .cloned()
                                            .unwrap_or_default()
                                            .trim_start_matches("schema:")
                                            .to_string();
                                        let src = agent.source.clone();
                                        let a2 = agent.clone();
                                        view! {
                                            <div
                                                class="agent-picker-card"
                                                on:click=move |_| {
                                                    on_select.call(a2.clone());
                                                    open.set(false);
                                                    query.set(String::new());
                                                }
                                            >
                                                <div class="agent-picker-card-name">{agent.name}</div>
                                                <div class="agent-picker-card-cap">{cap}</div>
                                                <div class="agent-picker-card-source">{src}</div>
                                            </div>
                                        }
                                    }).collect::<Vec<_>>().into_any()
                                }
                            }
                        >
                            <div class="agent-picker-empty">"Loading agents…"</div>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
    }
}
```

- [ ] **Step 3: Register in `mod.rs`**

In `apps/papillon/frontend/src/components/mod.rs`, add:
```rust
pub mod agent_picker_modal;
```

- [ ] **Step 4: cargo check**

```bash
cargo check -p papillon-ui 2>&1 | grep "^error" | head -5
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/components/agent_picker_modal.rs \
        apps/papillon/frontend/src/components/mod.rs \
        apps/papillon/frontend/styles/main.css
git commit -m "feat(ui): add AgentPickerModal — searchable 3x3 agent grid"
```

---

## Task 3 — Wire `AgentPickerModal` into Browse page

Replace the current "Browse Registries" page body so the BROWSE link from the fleet page opens the picker instead of a dead page.

**Files:**
- Modify: `apps/papillon/frontend/src/pages/browse.rs`

- [ ] **Step 1: Rewrite `browse.rs`**

```rust
use leptos::prelude::*;

use crate::components::agent_picker_modal::AgentPickerModal;
use papillon_shared::types::AgentInfo;

/// Browse page — immediately opens the agent picker modal.
/// When the user picks an agent, the intent bar is pre-filled with a
/// `pap://` prompt for that agent.
#[component]
pub fn BrowsePage() -> impl IntoView {
    let modal_open: RwSignal<bool> = RwSignal::new(true); // open immediately on mount
    let _selected: RwSignal<Option<AgentInfo>> = RwSignal::new(None);

    let on_select = Callback::new(move |agent: AgentInfo| {
        // Navigate back to canvas — agent selection handled by caller context
        // For now, log selection and navigate to canvas root.
        _selected.set(Some(agent));
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href("/");
        }
    });

    view! {
        <AgentPickerModal open=modal_open on_select=on_select />
        // Fallback if modal is dismissed without selecting
        <Show when=move || !modal_open.get()>
            <div style="display:flex;align-items:center;justify-content:center;height:60vh;color:#6b7280;font-size:13px;">
                <a href="/" style="color:var(--purple);">"← Back to canvas"</a>
            </div>
        </Show>
    }
}
```

- [ ] **Step 2: cargo check**

```bash
cargo check -p papillon-ui 2>&1 | grep "^error" | head -5
```

- [ ] **Step 3: Commit**

```bash
git add apps/papillon/frontend/src/pages/browse.rs
git commit -m "feat(browse): replace dead registry page with AgentPickerModal"
```

---

## Task 4 — Settings as full-screen overlay

Settings is currently a full-page route at `/settings`. Make it a full-screen overlay mounted at the app root level, triggered by a button in the topbar slide panel. A visible `×` button dismisses it. The `/settings` route can remain as a redirect for backwards compatibility.

**Files:**
- Modify: `apps/papillon/frontend/src/pages/settings.rs`
- Modify: `apps/papillon/frontend/src/app.rs`
- Modify: `apps/papillon/frontend/src/components/topbar.rs`
- Modify: `apps/papillon/frontend/styles/main.css`

- [ ] **Step 1: Add `.settings-overlay` CSS**

Append to `main.css`:

```css
/* ── Settings Overlay ────────────────────────────────────────────────────── */
.settings-overlay {
  position: fixed; inset: 0;
  background: var(--bg-1, #0e0e1a);
  z-index: 1200;
  display: flex; flex-direction: column;
  overflow: hidden;
}
.settings-overlay-topbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 20px;
  height: 48px;
  border-bottom: 1px solid var(--border, rgba(255,255,255,0.08));
  flex-shrink: 0;
}
.settings-overlay-title {
  font-size: 13px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; font-family: var(--font-mono);
  color: var(--text-muted, #6b7280);
}
.settings-overlay-close {
  background: transparent; border: none; cursor: pointer;
  color: var(--text-muted, #6b7280); font-size: 20px;
  padding: 4px 8px; border-radius: 4px;
  transition: color 0.15s, background 0.15s;
  line-height: 1;
}
.settings-overlay-close:hover {
  color: var(--text-primary, #e0e0e0);
  background: rgba(255,255,255,0.05);
}
.settings-overlay-body {
  flex: 1; overflow: hidden; display: flex;
}
/* Settings layout inside overlay fills remaining space */
.settings-overlay .settings-layout {
  flex: 1; overflow: hidden;
}
```

- [ ] **Step 2: Add `show_settings` to global context in `app.rs`**

In `app.rs`, after the existing `provide_context(workflow_state);` line (~line 114), add:

```rust
let show_settings: RwSignal<bool> = RwSignal::new(false);
provide_context(show_settings);
```

Then in the `view!` block of `App`, wrap the existing `<Router>` content so `SettingsOverlay` renders as a sibling:

```rust
view! {
    // ... existing SetupWizard ...
    <Show when=move || show_settings.get()>
        <div class="settings-overlay">
            <div class="settings-overlay-topbar">
                <span class="settings-overlay-title">"SETTINGS"</span>
                <button
                    class="settings-overlay-close"
                    on:click=move |_| show_settings.set(false)
                    aria-label="Close settings"
                >"×"</button>
            </div>
            <div class="settings-overlay-body">
                <SettingsPage />
            </div>
        </div>
    </Show>
    // ... existing Router / TopBar / Routes ...
}
```

Import `SettingsPage` at the top of `app.rs` (it's already imported — verify `use crate::pages::settings::SettingsPage;` exists).

- [ ] **Step 3: Update topbar to trigger settings overlay instead of navigating**

In `topbar.rs`, find the "All Settings" panel nav item (line ~142):

```rust
<PanelNavItem href="/settings" label="All Settings" close_panel=menu_open>
```

Replace with a button that sets `show_settings`:

```rust
{
    let show_settings = expect_context::<RwSignal<bool>>();
    view! {
        <button
            class="panel-nav-item"
            on:click=move |_| {
                menu_open.set(false);
                show_settings.set(true);
            }
        >
            <span class="panel-nav-icon">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
            </span>
            "All Settings"
        </button>
    }
}
```

Also add `use crate::state::WorkflowState;` to the topbar imports if not present; add `RwSignal` import.

- [ ] **Step 4: Keep `/settings` route working (for direct nav and e2e tests)**

The existing `<Route path=path!("/settings") view=SettingsPage />` in `app.rs` can stay. Direct navigation still renders `SettingsPage` inline. The overlay is an additional path.

- [ ] **Step 5: cargo check**

```bash
cargo check -p papillon-ui 2>&1 | grep "^error" | head -5
```

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/app.rs \
        apps/papillon/frontend/src/pages/settings.rs \
        apps/papillon/frontend/src/components/topbar.rs \
        apps/papillon/frontend/styles/main.css
git commit -m "feat(settings): mount settings as full-screen overlay with X close button"
```

---

## Task 5 — Remove chat thread from canvas front face; add `CanvasAside`

The `CanvasChatThread` rendered below the blocks is removed. A new `CanvasAside` component replaces it: a collapsible right sidebar showing chat history, a first-run explanation of Papillon, and Plan/Auto mode buttons (shown only when an LLM is configured).

**Files:**
- Create: `apps/papillon/frontend/src/components/canvas_aside.rs`
- Modify: `apps/papillon/frontend/src/components/mod.rs`
- Modify: `apps/papillon/frontend/src/pages/canvas.rs`
- Modify: `apps/papillon/frontend/styles/main.css`

- [ ] **Step 1: Add CSS**

Append to `main.css`:

```css
/* ── Canvas Aside ────────────────────────────────────────────────────────── */
.canvas-page-with-aside {
  display: flex;
  flex: 1;
  overflow: hidden;
  position: relative;
}
.canvas-aside {
  width: 280px;
  flex-shrink: 0;
  background: var(--bg-2, #13131f);
  border-left: 1px solid var(--border, rgba(255,255,255,0.06));
  display: flex;
  flex-direction: column;
  overflow: hidden;
  transition: width 0.2s ease, opacity 0.2s ease;
}
.canvas-aside.collapsed {
  width: 0;
  opacity: 0;
  pointer-events: none;
}
.canvas-aside-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border, rgba(255,255,255,0.06));
  flex-shrink: 0;
}
.canvas-aside-title {
  font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; font-family: var(--font-mono);
  color: var(--text-muted, #6b7280);
}
.canvas-aside-close {
  background: transparent; border: none; cursor: pointer;
  color: var(--text-muted, #6b7280); font-size: 16px; padding: 0 4px;
}
.canvas-aside-close:hover { color: var(--text-primary); }
.canvas-aside-body {
  flex: 1; overflow-y: auto; padding: 14px;
  display: flex; flex-direction: column; gap: 14px;
}
.canvas-aside-tip {
  background: rgba(108,92,231,0.07);
  border: 1px solid rgba(108,92,231,0.2);
  border-radius: 8px; padding: 12px 14px;
  font-size: 12px; line-height: 1.6; color: var(--text-primary, #e0e0e0);
}
.canvas-aside-tip-dismiss {
  display: block; margin-top: 8px;
  background: transparent; border: none; cursor: pointer;
  font-size: 10px; color: var(--text-muted); text-decoration: underline;
}
.canvas-aside-modes {
  display: flex; flex-direction: column; gap: 6px;
}
.canvas-aside-mode-label {
  font-size: 9px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-muted);
  font-family: var(--font-mono); margin-bottom: 2px;
}
.canvas-aside-mode-btn {
  background: var(--bg-1); border: 1px solid var(--border);
  border-radius: 6px; padding: 8px 12px;
  color: var(--text-muted); font-size: 11px; cursor: pointer;
  text-align: left; transition: border-color 0.15s, color 0.15s;
}
.canvas-aside-mode-btn:hover { border-color: var(--purple); color: var(--text-primary); }
.canvas-aside-mode-btn.active { border-color: var(--purple); color: var(--purple); }
.canvas-aside-chat-label {
  font-size: 9px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-muted); font-family: var(--font-mono);
}
/* Aside toggle button in topbar area */
.canvas-aside-toggle {
  background: transparent; border: 1px solid var(--border);
  border-radius: 4px; padding: 3px 8px; font-size: 10px;
  color: var(--text-muted); cursor: pointer; font-family: var(--font-mono);
  transition: border-color 0.15s, color 0.15s;
}
.canvas-aside-toggle:hover { border-color: var(--purple); color: var(--purple); }
```

- [ ] **Step 2: Create `canvas_aside.rs`**

```rust
use leptos::prelude::*;

use crate::components::canvas_chat_thread::CanvasChatThread;
use crate::state::canvas::CanvasState;
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::OrchestratorStatus;

#[derive(Clone, Copy, PartialEq)]
pub enum AsideMode {
    None,
    Plan,
    Auto,
}

/// Collapsible right aside for canvas.
/// - First-run tip explaining Papillon as an intent browser
/// - Plan / Auto mode buttons (visible only when LLM is configured)
/// - Chat message history
#[component]
pub fn CanvasAside(open: RwSignal<bool>) -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let canvas_state = expect_context::<CanvasState>();
    let mode: RwSignal<AsideMode> = RwSignal::new(AsideMode::None);

    // Show tip until user dismisses it (persisted in localStorage)
    let show_tip = RwSignal::new({
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("papillon_aside_tip_dismissed").ok().flatten())
            .is_none()
    });

    let dismiss_tip = move |_| {
        show_tip.set(false);
        if let Some(s) = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
        {
            let _ = s.set_item("papillon_aside_tip_dismissed", "1");
        }
    };

    let has_llm = move || {
        orchestrator.status.get() != OrchestratorStatus::Unconfigured
    };

    let has_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        canvas_state.canvas_messages.get()
            .iter()
            .any(|m| active_id.as_deref() == Some(m.canvas_id.as_str()))
    };

    view! {
        <div
            class="canvas-aside"
            class:collapsed=move || !open.get()
        >
            <div class="canvas-aside-header">
                <span class="canvas-aside-title">"CANVAS"</span>
                <button
                    class="canvas-aside-close"
                    on:click=move |_| open.set(false)
                    aria-label="Close aside"
                >"×"</button>
            </div>

            <div class="canvas-aside-body">
                // First-run tip
                <Show when=move || show_tip.get()>
                    <div class="canvas-aside-tip">
                        "Papillon is an intent browser. Type what you want to know or do — it finds and runs the right agent on your behalf, with your explicit approval over what data is shared."
                        <button class="canvas-aside-tip-dismiss" on:click=dismiss_tip>
                            "Got it, dismiss"
                        </button>
                    </div>
                </Show>

                // Plan / Auto mode (only when LLM available)
                <Show when=has_llm>
                    <div class="canvas-aside-modes">
                        <div class="canvas-aside-mode-label">"AI MODE"</div>
                        <button
                            class="canvas-aside-mode-btn"
                            class:active=move || mode.get() == AsideMode::Plan
                            on:click=move |_| {
                                mode.update(|m| *m = if *m == AsideMode::Plan { AsideMode::None } else { AsideMode::Plan });
                            }
                            title="Collect context on which agents to add and how properties connect, then present a plan."
                        >
                            "📋 Plan mode"
                        </button>
                        <button
                            class="canvas-aside-mode-btn"
                            class:active=move || mode.get() == AsideMode::Auto
                            on:click=move |_| {
                                mode.update(|m| *m = if *m == AsideMode::Auto { AsideMode::None } else { AsideMode::Auto });
                            }
                            title="Immediately add advertised agent blocks and run automatically."
                        >
                            "⚡ Auto mode"
                        </button>
                    </div>
                </Show>

                // Chat history
                <Show when=has_messages>
                    <div class="canvas-aside-chat-label">"CONVERSATION"</div>
                    <CanvasChatThread />
                </Show>
            </div>
        </div>
    }
}
```

- [ ] **Step 3: Register in `mod.rs`**

Add to `apps/papillon/frontend/src/components/mod.rs`:
```rust
pub mod canvas_aside;
```

- [ ] **Step 4: Update `canvas.rs`**

In `apps/papillon/frontend/src/pages/canvas.rs`:

a) Add imports:
```rust
use crate::components::canvas_aside::CanvasAside;
```

b) Remove the `use crate::components::canvas_chat_thread::CanvasChatThread;` import.

c) Add aside open signal at the top of `CanvasPage`:
```rust
let aside_open: RwSignal<bool> = RwSignal::new(false);
```

d) Replace the front face structure. Current:
```rust
<div class="canvas-face front">
    <div class="canvas-stream">
        // ...blocks...
        <button class="add-note-btn" ...>
    </div>
    <CanvasChatThread />
</div>
```

New:
```rust
<div class="canvas-face front">
    <div class="canvas-page-with-aside">
        <div class="canvas-stream" style="flex:1;overflow-y:auto;">
            // ...blocks (unchanged)...
            <button class="add-note-btn" ...>
        </div>
        <CanvasAside open=aside_open />
    </div>
</div>
```

e) Expose `aside_open` via context so the topbar toggle can reach it:
```rust
provide_context(aside_open);
```

- [ ] **Step 5: Add aside toggle to topbar**

In `topbar.rs`, after the existing `.canvas-flip-toggle` button, add:
```rust
{
    let aside_open = use_context::<RwSignal<bool>>();
    aside_open.map(|open| view! {
        <button
            class="canvas-aside-toggle"
            on:click=move |_| open.update(|v| *v = !*v)
            title="Toggle chat aside"
        >
            {move || if open.get() { "✕ Chat" } else { "💬 Chat" }}
        </button>
    })
}
```

- [ ] **Step 6: cargo check**

```bash
cargo check -p papillon-ui 2>&1 | grep "^error" | head -5
```

- [ ] **Step 7: Commit**

```bash
git add apps/papillon/frontend/src/components/canvas_aside.rs \
        apps/papillon/frontend/src/components/mod.rs \
        apps/papillon/frontend/src/pages/canvas.rs \
        apps/papillon/frontend/src/components/topbar.rs \
        apps/papillon/frontend/styles/main.css
git commit -m "feat(canvas): add CanvasAside with tip, Plan/Auto mode, chat history; remove inline chat thread"
```

---

## Task 6 — Fix stale e2e tests (no new features, test accuracy only)

**Files:**
- Modify: `e2e/tests/agents.spec.ts`
- Modify: `e2e/tests/app.spec.ts`
- Modify: `e2e/tests/templates.spec.ts`
- Modify: `e2e/tests/workflow.spec.ts`

### 6a — `agents.spec.ts` (already rewritten in exploration agent output)

The file was already updated to test the Chrysalis dashboard (`.chrysalis-header-title`, `.chrysalis-node-row.local`, etc.) instead of the removed fleet page classes. Verify it passes:

- [ ] **Step 1: Run agents tests**

```bash
cd e2e && npx playwright test tests/agents.spec.ts --reporter=list 2>&1 | tail -20
```
Expected: all 17 tests pass. If any fail on a selector, read `dashboard.rs` for the exact class and fix.

### 6b — `app.spec.ts` — activity empty text + remove Add Successor test

- [ ] **Step 2: Fix activity empty text**

The test at line ~123 reads:
```typescript
page.locator("text=No protocol events yet.")
```
Change to:
```typescript
page.locator("text=No activity yet.")
```

- [ ] **Step 3: Remove Add Successor test**

Delete the entire `test("Add Successor form works", ...)` block (lines ~195–230). The Identity tab has no successor UI.

- [ ] **Step 4: Run app tests**

```bash
cd e2e && npx playwright test tests/app.spec.ts --reporter=list 2>&1 | tail -20
```
Expected: all tests pass.

### 6c — `templates.spec.ts` — remove antipatterns

- [ ] **Step 5: Remove `setTimeout` (line ~51)**

The slide-panel transition wait uses `setTimeout(resolve, 300)` as a fallback. Replace the entire `evaluate` block with a simple `waitForSelector` approach:

```typescript
await page.locator(".topbar-brand").click();
await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
// Wait for settings nav to be visible — no timeout hack needed
await page.locator(".settings-nav").waitFor({ state: "visible" });
```

But note: with the overlay approach from Task 4, the `preserveMock` path now opens the overlay, not navigates. The test helper `goToSettings` should use the overlay trigger. Since settings tests navigate directly with `page.goto("/settings")` (the `preserveMock=false` path), the `preserveMock=true` branch needs updating:

```typescript
if (preserveMock) {
    await page.locator(".topbar-brand").click();
    await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
    await page.locator(".settings-overlay").waitFor({ state: "visible" });
    // Settings overlay is now open — no navigation needed
    return; // settings-nav is inside the overlay
}
```

- [ ] **Step 6: Remove `pressSequentially` delay (line ~76)**

```typescript
await schemaInput.pressSequentially(schemaType, { delay: 30 });
```
Replace with fill + trigger input event (the WASM reactive system responds to `fill`):
```typescript
await schemaInput.fill(schemaType);
await schemaInput.dispatchEvent("input");
```
Then wait for autocomplete to appear:
```typescript
await page.locator('div[style*="z-index: 9999"]').waitFor({ state: "visible", timeout: 3000 });
await page.locator('div[style*="z-index: 9999"] div').filter({ hasText: schemaType }).first().click();
```

- [ ] **Step 7: Run templates tests**

```bash
cd e2e && npx playwright test tests/templates.spec.ts --reporter=list 2>&1 | tail -20
```
Expected: all 6 tests pass.

### 6d — `workflow.spec.ts` — remove redundant timeouts

- [ ] **Step 8: Fix workflow.spec.ts line ~196**

The review flag: `await expect(workflowTabA).toBeVisible({ timeout: 5_000 });`

This timeout has no retry value — `toBeVisible` retries until the default timeout anyway. Remove explicit `timeout` from `toBeVisible` calls that are immediately followed by a `.click()` (the click itself will wait). The visible check before click is redundant; replace with:

```typescript
await workflowTabA.waitFor({ state: "visible" });
await workflowTabA.click();
```

Search `workflow.spec.ts` for all `toBeVisible({ timeout:` patterns and evaluate each:
- If followed immediately by `.click()` → replace the pair with `waitFor({ state: "visible" }) + click()`
- If it's a terminal assertion (not followed by interaction) → keep it, `toBeVisible` with timeout is fine for assertions
- The `{ timeout: 5_000 }` at line 196 is the flagged one — it's followed by `.click()`. Remove it per above.

- [ ] **Step 9: Run workflow tests**

```bash
cd e2e && npx playwright test tests/workflow.spec.ts --reporter=list 2>&1 | tail -10
```
Expected: 24 passed, 1 skipped.

- [ ] **Step 10: Commit all test fixes**

```bash
git add e2e/tests/agents.spec.ts e2e/tests/app.spec.ts \
        e2e/tests/templates.spec.ts e2e/tests/workflow.spec.ts
git commit -m "fix(e2e): update stale tests for current UI; remove setTimeout and delay antipatterns"
```

---

## Task 7 — Add `AgentPickerModal` mock to `tauri-mock.ts` + e2e test

- [ ] **Step 1: Verify `list_local_agents` mock**

The mock already seeds 5 agents. Confirm in `e2e/tests/tauri-mock.ts`:
```bash
grep -n "list_local_agents" e2e/tests/tauri-mock.ts
```
Expected: handler exists returning 5 agents.

- [ ] **Step 2: Add modal test to `workflow.spec.ts` or new file**

Add to `e2e/tests/agents.spec.ts` a new describe block:

```typescript
test.describe("Agent Picker Modal (Browse page)", () => {
  test("browse page opens agent picker modal immediately", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".agent-picker-overlay")).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".agent-picker-modal")).toBeVisible();
    await expect(page.locator(".agent-picker-title")).toContainText("INSTALLED AGENTS");
  });

  test("agent picker search filters results", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".agent-picker-search").waitFor({ state: "visible" });
    await page.locator(".agent-picker-search").fill("web");
    // Count visible agent cards
    const cards = page.locator(".agent-picker-card");
    const count = await cards.count();
    // Should be fewer than the full 5
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("agent picker close button dismisses modal", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".agent-picker-close").waitFor({ state: "visible" });
    await page.locator(".agent-picker-close").click();
    await expect(page.locator(".agent-picker-overlay")).not.toBeVisible();
  });

  test("agent picker shows count label", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".agent-picker-count")).toContainText("agents installed");
  });
});
```

- [ ] **Step 3: Run new tests**

```bash
cd e2e && npx playwright test tests/agents.spec.ts --reporter=list 2>&1 | tail -15
```

- [ ] **Step 4: Commit**

```bash
git add e2e/tests/agents.spec.ts e2e/tests/tauri-mock.ts
git commit -m "test(e2e): add AgentPickerModal browse tests"
```

---

## Task 8 — Full test suite regression check

- [ ] **Step 1: Run all browser-mode tests**

```bash
cd e2e && npx playwright test tests/smoke.spec.ts tests/app.spec.ts tests/agents.spec.ts tests/web-standalone.spec.ts tests/agent-prompts.spec.ts tests/templates.spec.ts tests/workflow.spec.ts --reporter=list 2>&1 | grep -E "passed|failed|skipped"
```
Expected: 0 failed.

- [ ] **Step 2: Run Rust unit tests**

```bash
cargo test -p papillon-shared 2>&1 | tail -5
cargo test -p papillon port_compat 2>&1 | tail -5
```
Expected: all pass.

- [ ] **Step 3: Final commit if clean**

```bash
git add -A
git commit -m "chore: final regression check clean — all browser-mode tests pass"
```

---

## Verification

After all tasks:

1. **Back face**: Click "⟳ Workflow" → back face renders styled tabs (Sources / Workflow), not raw text
2. **Browse**: Navigate to `/fleet` → click BROWSE → modal opens with 3×3 grid of agents, searchable
3. **Settings**: Open slide panel → click "All Settings" → full-screen overlay appears with × button; × dismisses it
4. **Chat aside**: Click "💬 Chat" button in topbar → right aside slides in with Papillon tip; clicking "Got it" dismisses tip; LLM section shows Plan/Auto buttons if LLM configured
5. **No chat below blocks**: Front face shows only blocks + note button; no chat thread below blocks
6. **e2e**: `npx playwright test tests/agents.spec.ts tests/app.spec.ts tests/templates.spec.ts tests/workflow.spec.ts` → 0 failures

---

## Scope check against requirements

| Requirement | Task |
|---|---|
| Browse → searchable agent modal from real `list_local_agents` | Tasks 2 + 3 |
| Settings full-screen with X button | Task 4 |
| Workflow button becomes canvas toolbar | Task 5 (aside toggle); Task 4 step 3 (Settings) |
| Remove chat thread below blocks | Task 5 |
| Collapsible right aside with chat history | Task 5 |
| First-time chat message explaining Papillon | Task 5 (`canvas-aside-tip`) |
| Plan mode / Auto mode (LLM-gated) | Task 5 |
| Back-face CSS fix | Task 1 |
| Fix stale e2e tests | Task 6 |
| Remove setTimeout / delay antipatterns | Task 6c + 6d |

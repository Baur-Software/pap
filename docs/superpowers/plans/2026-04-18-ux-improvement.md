# UX Improvement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the sidebar, replace the topbar dropdown with a slide-in panel for navigation/canvas management, reorganize Settings from 6 flat tabs to a left-nav layout with an Appearance section, and fix the invisible canvas delete button.

**Architecture:** All changes are pure frontend (Rust/Leptos + CSS). The existing `menu_open: RwSignal<bool>` in `topbar.rs` becomes the panel open/close signal. `settings.rs` keeps its `active_tab` signal but replaces the tab bar markup with left-nav markup and adds a new `AppearanceTab` component. Theme/accent state is stored in `localStorage` and applied via `data-theme` attribute and CSS custom properties.

**Tech Stack:** Rust, Leptos (reactive signals, `view!` macro, `Effect::new`), `wasm-bindgen`, `web_sys` for localStorage/DOM attribute access, Playwright for e2e tests.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `apps/papillon/frontend/src/components/sidebar.rs` | **Delete** | Removed entirely |
| `apps/papillon/frontend/src/components/topbar.rs` | **Modify** | Slide-in panel replaces dropdown |
| `apps/papillon/frontend/src/components/mod.rs` | **Modify** | Remove `sidebar` module declaration |
| `apps/papillon/frontend/src/pages/settings.rs` | **Modify** | Left nav + AppearanceTab |
| `apps/papillon/frontend/src/app.rs` | **Modify** | Remove Sidebar, add theme init on startup |
| `apps/papillon/frontend/styles/main.css` | **Modify** | Grid, panel, delete button, settings nav, appearance |
| `e2e/tests/app.spec.ts` | **Modify** | Update tests for panel (no `.menu-dropdown`) |
| `e2e/tests/web-standalone.spec.ts` | **Modify** | Update settings nav tests, panel tests |

---

## Task 1: CSS — Grid, Panel, Delete Button Fix

Get all CSS in place first so Rust changes immediately render correctly.

**Files:**
- Modify: `apps/papillon/frontend/styles/main.css`

- [ ] **Step 1: Collapse the app shell grid from 2 columns to 1**

Find this block (around line 967):
```css
.app-shell-canvas {
    display: grid;
    grid-template-columns: var(--sidebar-width) 1fr;
    grid-template-rows: var(--header-height) 1fr var(--status-height);
    height: 100vh;
    overflow: hidden;
    background-color: #0d1117;
    background-image: radial-gradient(circle, var(--dot-grid-color) 1px, transparent 1px);
    background-size: var(--dot-grid-size) var(--dot-grid-size);
}
```

Replace `grid-template-columns: var(--sidebar-width) 1fr;` with:
```css
    grid-template-columns: 1fr;
```

Find `.app-main` (around line 989):
```css
.app-main {
    grid-column: 2;
    grid-row: 2;
    overflow: hidden;
}
```
Change to:
```css
.app-main {
    grid-column: 1;
    grid-row: 2;
    overflow: hidden;
}
```

- [ ] **Step 2: Fix the canvas delete button visibility**

Find `.menu-item-delete` (around line 1352):
```css
.menu-item-delete {
    flex-shrink: 0;
    background: none;
    border: none;
    color: rgba(255,255,255,0.25);
    cursor: pointer;
    padding: 0 10px;
    font-size: 16px;
    line-height: 1;
    transition: color 0.15s ease;
}
```

Change `color: rgba(255,255,255,0.25)` to `color: var(--text-2)`:
```css
.menu-item-delete {
    flex-shrink: 0;
    background: none;
    border: none;
    color: var(--text-2);
    cursor: pointer;
    padding: 0 10px;
    font-size: 16px;
    line-height: 1;
    transition: color 0.15s ease;
}
```

- [ ] **Step 3: Add slide-in panel CSS**

After the `.menu-backdrop` block (around line 1368), add:

```css
/* ═══════════════════════════════════════════════════════════
   SLIDE-IN PANEL
   ═══════════════════════════════════════════════════════════ */

.slide-panel {
    position: fixed;
    top: var(--topbar-height);
    left: 0;
    bottom: var(--status-height);
    width: 272px;
    background: var(--bg-1);
    border-right: 1px solid var(--border);
    z-index: 200;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    transform: translateX(-100%);
    transition: transform 200ms ease;
}

.slide-panel.open {
    transform: translateX(0);
}

.slide-panel-backdrop {
    position: fixed;
    top: var(--topbar-height);
    left: 0;
    right: 0;
    bottom: var(--status-height);
    background: rgba(12, 11, 20, 0.55);
    z-index: 199;
    opacity: 0;
    pointer-events: none;
    transition: opacity 100ms ease;
}

.slide-panel-backdrop.open {
    opacity: 1;
    pointer-events: all;
}

.panel-body {
    flex: 1;
    overflow-y: auto;
    padding: 10px 0;
}

.panel-section-label {
    padding: 10px 16px 4px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-3);
    font-family: var(--font-mono);
}

.panel-canvas-item {
    display: flex;
    align-items: center;
    padding: 0 8px 0 14px;
    height: 34px;
    border-radius: var(--r-md);
    margin: 1px 8px;
    cursor: pointer;
    transition: background 0.12s;
    gap: 9px;
}

.panel-canvas-item:hover {
    background: var(--bg-2);
}

.panel-canvas-item.active {
    background: rgba(108, 92, 231, 0.12);
}

.panel-canvas-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--border);
    transition: background 0.12s;
}

.panel-canvas-dot.active {
    background: var(--purple);
    box-shadow: 0 0 5px var(--purple-glow);
}

.panel-canvas-name {
    flex: 1;
    font-size: 13px;
    color: var(--text-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.panel-canvas-item.active .panel-canvas-name {
    color: var(--text-1);
    font-weight: 500;
}

.panel-canvas-actions {
    display: flex;
    gap: 2px;
    opacity: 0;
    transition: opacity 0.12s;
}

.panel-canvas-item:hover .panel-canvas-actions {
    opacity: 1;
}

.panel-canvas-btn {
    width: 22px;
    height: 22px;
    border-radius: var(--r-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    color: var(--text-3);
    cursor: pointer;
    transition: all 0.12s;
    background: none;
    border: none;
}

.panel-canvas-btn:hover {
    background: var(--bg-3);
    color: var(--text-2);
}

.panel-canvas-btn.delete:hover {
    background: rgba(232, 112, 106, 0.18);
    color: var(--coral);
}

.panel-new-canvas-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 14px;
    height: 32px;
    border-radius: var(--r-md);
    margin: 3px 8px;
    cursor: pointer;
    color: var(--purple);
    font-size: 13px;
    font-weight: 500;
    transition: background 0.12s;
    background: none;
    border: none;
    width: calc(100% - 16px);
    text-align: left;
    font-family: var(--font-body);
}

.panel-new-canvas-btn:hover {
    background: rgba(108, 92, 231, 0.1);
}

.panel-kbd {
    margin-left: auto;
    font-size: 10px;
    background: var(--bg-2);
    color: var(--text-3);
    padding: 2px 5px;
    border-radius: var(--r-sm);
    font-family: var(--font-mono);
    border: 1px solid var(--border);
}

.panel-divider {
    height: 1px;
    background: var(--border-subtle);
    margin: 8px 0;
}

.panel-nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 16px;
    height: 34px;
    border-radius: var(--r-md);
    margin: 1px 8px;
    cursor: pointer;
    color: var(--text-2);
    font-size: 13px;
    font-family: var(--font-body);
    transition: all 0.12s;
    background: none;
    border: none;
    width: calc(100% - 16px);
    text-align: left;
    text-decoration: none;
}

.panel-nav-item:hover {
    background: var(--bg-2);
    color: var(--text-1);
}

.panel-nav-item.active {
    background: rgba(108, 92, 231, 0.1);
    color: var(--purple);
}

.panel-nav-icon {
    width: 16px;
    text-align: center;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
}

.panel-theme-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 16px;
    height: 34px;
    border-radius: var(--r-md);
    margin: 1px 8px;
    font-size: 13px;
    color: var(--text-2);
    font-family: var(--font-body);
}

.panel-theme-pills {
    margin-left: auto;
    display: flex;
    gap: 2px;
    background: var(--bg-2);
    border-radius: var(--r-sm);
    padding: 2px;
    border: 1px solid var(--border);
}

.panel-theme-pill {
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 3px;
    color: var(--text-3);
    cursor: pointer;
    font-family: var(--font-mono);
    background: none;
    border: none;
    transition: all 0.12s;
}

.panel-theme-pill.active {
    background: var(--bg-3);
    color: var(--text-1);
}
```

- [ ] **Step 4: Add Settings left-nav CSS**

After the existing `.settings-tab-bar` / `.settings-tab` CSS block, add new rules (keep old ones for now — they'll be removed when settings.rs is updated):

```css
/* ═══════════════════════════════════════════════════════════
   SETTINGS — LEFT NAV LAYOUT
   ═══════════════════════════════════════════════════════════ */

.settings-layout {
    display: flex;
    height: 100%;
    overflow: hidden;
}

.settings-nav {
    width: 200px;
    flex-shrink: 0;
    background: var(--bg-0);
    border-right: 1px solid var(--border-subtle);
    padding: 16px 0;
    overflow-y: auto;
}

.settings-nav-group-label {
    padding: 10px 16px 4px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-3);
    font-family: var(--font-mono);
}

.settings-nav-link {
    display: flex;
    align-items: center;
    gap: 9px;
    padding: 0 16px;
    height: 32px;
    font-size: 13px;
    color: var(--text-2);
    cursor: pointer;
    transition: all 0.12s;
    border-left: 2px solid transparent;
    background: none;
    border-top: none;
    border-right: none;
    border-bottom: none;
    width: 100%;
    text-align: left;
    font-family: var(--font-body);
}

.settings-nav-link:hover {
    color: var(--text-1);
    background: rgba(255, 255, 255, 0.03);
}

.settings-nav-link.active {
    color: var(--text-1);
    font-weight: 500;
    border-left-color: var(--purple);
    background: rgba(108, 92, 231, 0.08);
}

.settings-nav-icon {
    width: 14px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
}

.settings-nav-divider {
    height: 1px;
    background: var(--border-subtle);
    margin: 8px 0;
}

.settings-content {
    flex: 1;
    overflow-y: auto;
    padding: 28px 36px;
    background: var(--bg-0);
}

.settings-section-title {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-1);
    letter-spacing: -0.02em;
    margin-bottom: 4px;
}

.settings-section-desc {
    font-size: 12px;
    color: var(--text-3);
    margin-bottom: 24px;
    line-height: 1.5;
}

.settings-group {
    margin-bottom: 20px;
    background: var(--bg-1);
    border: 1px solid var(--border-subtle);
    border-radius: var(--r-md);
    overflow: hidden;
}

.settings-row {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 13px 16px;
    border-bottom: 1px solid var(--border-subtle);
}

.settings-row:last-child {
    border-bottom: none;
}

.settings-row-label {
    flex: 1;
}

.settings-row-label strong {
    display: block;
    font-size: 13px;
    color: var(--text-1);
    font-weight: 500;
    margin-bottom: 2px;
}

.settings-row-label span {
    font-size: 11px;
    color: var(--text-3);
    line-height: 1.4;
}

.settings-row-control {
    flex-shrink: 0;
}

/* Appearance: theme pills */
.appearance-theme-pills {
    display: flex;
    gap: 3px;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: 3px;
}

.appearance-theme-pill {
    font-size: 11px;
    padding: 4px 14px;
    border-radius: var(--r-sm);
    color: var(--text-3);
    cursor: pointer;
    font-family: var(--font-mono);
    background: none;
    border: none;
    transition: all 0.12s;
    font-size: 11px;
}

.appearance-theme-pill.active {
    background: var(--purple);
    color: white;
}

/* Appearance: accent swatches */
.appearance-swatches {
    display: flex;
    gap: 8px;
}

.appearance-swatch {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    cursor: pointer;
    border: 2px solid transparent;
    transition: transform 0.12s, border-color 0.12s;
    background: none;
    padding: 0;
}

.appearance-swatch:hover {
    transform: scale(1.1);
}

.appearance-swatch.active {
    border-color: var(--text-1);
    transform: scale(1.15);
}

/* Appearance: toggle switch */
.appearance-toggle {
    width: 36px;
    height: 20px;
    border-radius: 10px;
    background: var(--border);
    position: relative;
    cursor: pointer;
    border: none;
    transition: background 0.15s;
    flex-shrink: 0;
}

.appearance-toggle.on {
    background: var(--purple);
}

.appearance-toggle::after {
    content: '';
    position: absolute;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: white;
    top: 3px;
    left: 3px;
    transition: left 0.15s;
}

.appearance-toggle.on::after {
    left: 19px;
}

/* Appearance: font size select */
.appearance-select {
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    color: var(--text-2);
    font-size: 12px;
    padding: 4px 28px 4px 10px;
    font-family: var(--font-body);
    cursor: pointer;
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg width='10' height='6' viewBox='0 0 10 6' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%235c5b70' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 8px center;
}

/* Reduce motion */
@media (prefers-reduced-motion: reduce) {
    .slide-panel, .slide-panel-backdrop {
        transition: none;
    }
}

[data-reduce-motion="true"] * {
    transition: none !important;
    animation: none !important;
}

/* Compact density */
[data-compact="true"] .panel-canvas-item,
[data-compact="true"] .panel-nav-item,
[data-compact="true"] .panel-theme-row {
    height: 28px;
}

[data-compact="true"] .settings-row {
    padding: 9px 16px;
}
```

- [ ] **Step 5: Commit the CSS changes**

```bash
cd apps/papillon/frontend
git add styles/main.css
git commit -m "style: slide-in panel, settings left-nav, delete button fix, appearance controls"
```

---

## Task 2: Remove the Sidebar

**Files:**
- Delete: `apps/papillon/frontend/src/components/sidebar.rs`
- Modify: `apps/papillon/frontend/src/components/mod.rs`
- Modify: `apps/papillon/frontend/src/app.rs`

- [ ] **Step 1: Check what mod.rs declares**

```bash
cat apps/papillon/frontend/src/components/mod.rs
```

Look for a line like `pub mod sidebar;`.

- [ ] **Step 2: Remove the sidebar module declaration from mod.rs**

Open `apps/papillon/frontend/src/components/mod.rs` and delete the line:
```rust
pub mod sidebar;
```

- [ ] **Step 3: Remove Sidebar from app.rs**

In `apps/papillon/frontend/src/app.rs`, remove the import:
```rust
use crate::components::sidebar::Sidebar;
```

In the `view!` macro in `app.rs`, remove the `<Sidebar />` component:
```rust
// DELETE this line from the view! block:
<Sidebar />
```

- [ ] **Step 4: Delete sidebar.rs**

```bash
rm apps/papillon/frontend/src/components/sidebar.rs
```

- [ ] **Step 5: Verify it compiles**

```bash
cd apps/papillon/frontend
trunk build 2>&1 | tail -20
```

Expected: build succeeds (no errors referencing Sidebar or sidebar).

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/components/mod.rs \
        apps/papillon/frontend/src/app.rs
git rm apps/papillon/frontend/src/components/sidebar.rs
git commit -m "feat: remove sidebar — navigation moves to slide-in panel"
```

---

## Task 3: Topbar — Slide-In Panel

Replace the existing dropdown (`<div class="menu-dropdown">`) with a full-height slide-in panel. The trigger (`topbar-brand` button + `menu_open` signal) stays the same.

**Files:**
- Modify: `apps/papillon/frontend/src/components/topbar.rs`

- [ ] **Step 1: Add `use leptos_router::hooks::use_location;` import**

At the top of `topbar.rs`, the existing imports are:
```rust
use leptos::prelude::*;
use leptos::{ev, html};
use leptos_router::components::A;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::state::canvas::{CanvasSide, CanvasState};
use crate::state::catalog::CatalogState;
```

Add after the existing imports:
```rust
use leptos_router::hooks::use_location;
```

- [ ] **Step 2: Replace the entire `TopBar` component view! block**

Find the `TopBar` component — everything from `#[component]` to the closing `}` of the function. Replace the full `view!` block (the `view! { ... }` starting at the `<header>`) with:

```rust
    view! {
        <header class="topbar app-topbar">
            <button class="topbar-brand" on:click=toggle_menu title="Menu">
                <img class="topbar-brand-icon" src="/logo.png" alt="Papillon" />
                <span class="topbar-brand-name">"Papillon"</span>
            </button>

            <div class="topbar-address">
                <TopbarPrompt />
            </div>

            <div class="topbar-end">
                <button
                    class="canvas-flip-toggle"
                    on:click=toggle_side
                >
                    {move || if is_back() { "\u{27f3} Rendered" } else { "\u{27f3} Workflow" }}
                </button>
            </div>
        </header>

        // Backdrop — click to close
        <Show when=move || menu_open.get()>
            <div
                class=move || if menu_open.get() { "slide-panel-backdrop open" } else { "slide-panel-backdrop" }
                on:click=close_menu
            />
        </Show>

        // Slide-in panel
        <div class=move || if menu_open.get() { "slide-panel open" } else { "slide-panel" }>
            <div class="panel-body">

                // ── Canvases ──
                <div class="panel-section-label">"Canvases"</div>
                <For
                    each=canvases
                    key=|c| c.id.clone()
                    children=move |canvas| {
                        let cid_switch = canvas.id.clone();
                        let cid_delete = canvas.id.clone();
                        let cid_class  = canvas.id.clone();
                        view! {
                            <div
                                class=move || if active_id().as_deref() == Some(&cid_class) {
                                    "panel-canvas-item active"
                                } else {
                                    "panel-canvas-item"
                                }
                                on:click=move |_| {
                                    canvas_state.current_canvas_id.set(Some(cid_switch.clone()));
                                    menu_open.set(false);
                                }
                            >
                                <div class=move || if active_id().as_deref() == Some(&canvas.id) {
                                    "panel-canvas-dot active"
                                } else {
                                    "panel-canvas-dot"
                                } />
                                <span class="panel-canvas-name">{canvas.name.clone()}</span>
                                <div class="panel-canvas-actions">
                                    <button
                                        class="panel-canvas-btn delete"
                                        title="Delete canvas"
                                        on:click=move |e| {
                                            e.stop_propagation();
                                            canvas_state.delete_canvas(&cid_delete);
                                        }
                                    >
                                        "\u{00d7}"
                                    </button>
                                </div>
                            </div>
                        }
                    }
                />
                <button
                    class="panel-new-canvas-btn"
                    on:click=move |_| {
                        canvas_state.new_canvas();
                        menu_open.set(false);
                    }
                >
                    <span>"+ New Canvas"</span>
                    <span class="panel-kbd">"\u{2318}K"</span>
                </button>

                <div class="panel-divider" />

                // ── Navigate ──
                <div class="panel-section-label">"Navigate"</div>
                <PanelNavItem href="/browse" label="Browse Agents" close_panel=menu_open>
                    <IconLayers />
                </PanelNavItem>
                <PanelNavItem href="/fleet" label="Fleet" close_panel=menu_open>
                    <IconChip />
                </PanelNavItem>
                <PanelNavItem href="/receipts" label="Receipts" close_panel=menu_open>
                    <IconHistory />
                </PanelNavItem>

                <div class="panel-divider" />

                // ── Settings ──
                <div class="panel-section-label">"Settings"</div>
                <ThemeToggleRow />
                <PanelNavItem href="/settings" label="All Settings" close_panel=menu_open>
                    <IconGear />
                </PanelNavItem>

            </div>
        </div>
    }
```

- [ ] **Step 3: Add helper components at the bottom of topbar.rs**

After the `TopbarPrompt` component (and its closing `}`), add:

```rust
/// A nav link row inside the slide panel. Closes the panel on click.
#[component]
fn PanelNavItem(
    href: &'static str,
    label: &'static str,
    close_panel: RwSignal<bool>,
    children: Children,
) -> impl IntoView {
    let location = use_location();
    let href_str = href;
    view! {
        <A
            href=href
            attr:class=move || {
                if location.pathname.get().starts_with(href_str) {
                    "panel-nav-item active"
                } else {
                    "panel-nav-item"
                }
            }
            on:click=move |_| close_panel.set(false)
        >
            <span class="panel-nav-icon">{children()}</span>
            {label}
        </A>
    }
}

/// Inline Dark / Light / Auto theme toggle row.
/// Reads/writes data-theme on <html> and persists to localStorage.
#[component]
fn ThemeToggleRow() -> impl IntoView {
    let theme = RwSignal::new(
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("papillon_theme").ok().flatten())
            .unwrap_or_else(|| "dark".to_string()),
    );

    let set_theme = move |t: &'static str| {
        theme.set(t.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element()
                    .map(|el| el.set_attribute("data-theme", t));
            }
            if let Ok(Some(storage)) = win.local_storage() {
                let _ = storage.set_item("papillon_theme", t);
            }
        }
    };

    view! {
        <div class="panel-theme-row">
            <span class="panel-nav-icon">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <circle cx="12" cy="12" r="4"/>
                    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41
                             M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
                </svg>
            </span>
            <span>"Theme"</span>
            <div class="panel-theme-pills">
                <button
                    class=move || if theme.get() == "light" { "panel-theme-pill active" } else { "panel-theme-pill" }
                    on:click=move |_| set_theme("light")
                >"Light"</button>
                <button
                    class=move || if theme.get() == "dark" { "panel-theme-pill active" } else { "panel-theme-pill" }
                    on:click=move |_| set_theme("dark")
                >"Dark"</button>
                <button
                    class=move || if theme.get() == "auto" { "panel-theme-pill active" } else { "panel-theme-pill" }
                    on:click=move |_| set_theme("auto")
                >"Auto"</button>
            </div>
        </div>
    }
}

// ── Icons used by panel nav items ────────────────────────────

#[component]
fn IconLayers() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="12 2 2 7 12 12 22 7 12 2"/>
            <polyline points="2 17 12 22 22 17"/>
            <polyline points="2 12 12 17 22 12"/>
        </svg>
    }
}

#[component]
fn IconChip() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="6" height="6" rx="1"/>
            <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>
            <rect x="4" y="4" width="16" height="16" rx="2"/>
        </svg>
    }
}

#[component]
fn IconHistory() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="1 4 1 10 7 10"/>
            <path d="M3.51 15a9 9 0 1 0 .49-4.5"/>
            <polyline points="12 7 12 12 15 15"/>
        </svg>
    }
}

#[component]
fn IconGear() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06
                     a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09
                     A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83
                     l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09
                     A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83
                     l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09
                     a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83
                     l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09
                     a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
    }
}
```

- [ ] **Step 4: Build to verify no compile errors**

```bash
cd apps/papillon/frontend
trunk build 2>&1 | tail -30
```

Expected: build succeeds. If Leptos complains about `Children` type, check that `use leptos::prelude::*` includes it (it does in Leptos 0.7+).

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/components/topbar.rs
git commit -m "feat(topbar): replace dropdown with slide-in panel"
```

---

## Task 4: App.rs — Theme Init on Startup

Read `localStorage["papillon_theme"]` on app startup and apply `data-theme` to `<html>` before first render.

**Files:**
- Modify: `apps/papillon/frontend/src/app.rs`

- [ ] **Step 1: Add theme init at the top of the `App` component body**

In `app.rs`, find the `App` component function body (starts after `pub fn App() -> impl IntoView {`). Before the first `let identity_state = ...` line, add:

```rust
    // Apply persisted theme on startup
    if let Some(win) = web_sys::window() {
        let stored_theme = win
            .local_storage()
            .ok()
            .flatten()
            .and_then(|s| s.get_item("papillon_theme").ok().flatten())
            .unwrap_or_else(|| "dark".to_string());
        if let Some(doc) = win.document() {
            let _ = doc
                .document_element()
                .map(|el| el.set_attribute("data-theme", &stored_theme));
        }
    }
```

- [ ] **Step 2: Build to verify**

```bash
cd apps/papillon/frontend
trunk build 2>&1 | tail -20
```

- [ ] **Step 3: Commit**

```bash
git add apps/papillon/frontend/src/app.rs
git commit -m "feat(app): apply persisted theme from localStorage on startup"
```

---

## Task 5: Settings Page — Left Nav + Appearance Tab

**Files:**
- Modify: `apps/papillon/frontend/src/pages/settings.rs`

- [ ] **Step 1: Update the `SettingsPage` component**

Find the `SettingsPage` component. Replace only the `view!` block (the `view! { ... }` portion, not the `let active_tab` signal declaration):

```rust
#[component]
pub fn SettingsPage() -> impl IntoView {
    let active_tab = RwSignal::new("profiles".to_string());

    view! {
        <div class="settings-page settings-layout">

            // ── Left nav ──
            <nav class="settings-nav">

                <div class="settings-nav-group-label">"Account"</div>
                <button
                    class=move || if active_tab.get() == "profiles" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("profiles".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    "Profiles"
                </button>
                <button
                    class=move || if active_tab.get() == "identity" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("identity".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </span>
                    "Identity"
                </button>

                <div class="settings-nav-divider" />
                <div class="settings-nav-group-label">"AI"</div>
                <button
                    class=move || if active_tab.get() == "model" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("model".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
                    </span>
                    "Model"
                </button>
                <button
                    class=move || if active_tab.get() == "templates" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("templates".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    </span>
                    "Templates"
                </button>

                <div class="settings-nav-divider" />
                <div class="settings-nav-group-label">"Security"</div>
                <button
                    class=move || if active_tab.get() == "access-control" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("access-control".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </span>
                    "Access Control"
                </button>
                <button
                    class=move || if active_tab.get() == "advanced" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("advanced".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    </span>
                    "Advanced"
                </button>

                <div class="settings-nav-divider" />
                <div class="settings-nav-group-label">"Appearance"</div>
                <button
                    class=move || if active_tab.get() == "appearance" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("appearance".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
                    </span>
                    "Appearance"
                </button>

            </nav>

            // ── Content ──
            <div class="settings-content">
                <Show when=move || active_tab.get() == "profiles">
                    <ProfilesTab />
                </Show>
                <Show when=move || active_tab.get() == "identity">
                    <IdentityTab />
                </Show>
                <Show when=move || active_tab.get() == "model">
                    <GeneralTab />
                </Show>
                <Show when=move || active_tab.get() == "templates">
                    <TemplatesTab />
                </Show>
                <Show when=move || active_tab.get() == "access-control">
                    <MandateBuilderTab />
                </Show>
                <Show when=move || active_tab.get() == "advanced">
                    <AdvancedTab />
                </Show>
                <Show when=move || active_tab.get() == "appearance">
                    <AppearanceTab />
                </Show>
            </div>

        </div>
    }
}
```

- [ ] **Step 2: Add the `AppearanceTab` component**

At the bottom of `settings.rs` (before the final `}`), add:

```rust
#[component]
fn AppearanceTab() -> impl IntoView {
    // Read initial values from localStorage / current data-theme
    let stored_theme = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_theme").ok().flatten())
        .unwrap_or_else(|| "dark".to_string());

    let stored_accent = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_accent").ok().flatten())
        .unwrap_or_else(|| "#6c5ce7".to_string());

    let stored_font_size = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_font_size").ok().flatten())
        .unwrap_or_else(|| "medium".to_string());

    let stored_reduce_motion = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_reduce_motion").ok().flatten())
        .map(|v| v == "true")
        .unwrap_or(false);

    let stored_compact = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_compact").ok().flatten())
        .map(|v| v == "true")
        .unwrap_or(false);

    let theme      = RwSignal::new(stored_theme);
    let accent     = RwSignal::new(stored_accent);
    let font_size  = RwSignal::new(stored_font_size);
    let reduce_motion = RwSignal::new(stored_reduce_motion);
    let compact    = RwSignal::new(stored_compact);

    // Helpers
    let apply_theme = move |t: &'static str| {
        theme.set(t.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element().map(|el| el.set_attribute("data-theme", t));
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_theme", t);
            }
        }
    };

    let apply_accent = move |color: &'static str| {
        accent.set(color.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let style = doc.document_element()
                    .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
                    .map(|el| el.style());
                if let Some(style) = style {
                    let _ = style.set_property("--purple", color);
                }
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_accent", color);
            }
        }
    };

    let apply_font_size = move |size: &'static str| {
        let scale = match size { "small" => "0.9", "large" => "1.1", _ => "1.0" };
        font_size.set(size.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let style = doc.document_element()
                    .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
                    .map(|el| el.style());
                if let Some(style) = style {
                    let _ = style.set_property("--font-scale", scale);
                }
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_font_size", size);
            }
        }
    };

    let toggle_reduce_motion = move |_| {
        let next = !reduce_motion.get_untracked();
        reduce_motion.set(next);
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element()
                    .map(|el| el.set_attribute("data-reduce-motion", if next { "true" } else { "false" }));
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_reduce_motion", if next { "true" } else { "false" });
            }
        }
    };

    let toggle_compact = move |_| {
        let next = !compact.get_untracked();
        compact.set(next);
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element()
                    .map(|el| el.set_attribute("data-compact", if next { "true" } else { "false" }));
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_compact", if next { "true" } else { "false" });
            }
        }
    };

    view! {
        <div class="settings-section-title">"Appearance"</div>
        <p class="settings-section-desc">"Customize how Papillon looks. Changes apply immediately."</p>

        <div class="settings-group">
            // Theme
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Theme"</strong>
                    <span>"Light or dark interface, or follow your system preference"</span>
                </div>
                <div class="settings-row-control">
                    <div class="appearance-theme-pills">
                        <button
                            class=move || if theme.get() == "light" { "appearance-theme-pill active" } else { "appearance-theme-pill" }
                            on:click=move |_| apply_theme("light")
                        >"Light"</button>
                        <button
                            class=move || if theme.get() == "dark" { "appearance-theme-pill active" } else { "appearance-theme-pill" }
                            on:click=move |_| apply_theme("dark")
                        >"Dark"</button>
                        <button
                            class=move || if theme.get() == "auto" { "appearance-theme-pill active" } else { "appearance-theme-pill" }
                            on:click=move |_| apply_theme("auto")
                        >"Auto"</button>
                    </div>
                </div>
            </div>

            // Accent color
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Accent color"</strong>
                    <span>"Used for active states, highlights, and interactive elements"</span>
                </div>
                <div class="settings-row-control">
                    <div class="appearance-swatches">
                        <button class=move || if accent.get() == "#6c5ce7" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#6c5ce7" title="Purple (default)" on:click=move |_| apply_accent("#6c5ce7") />
                        <button class=move || if accent.get() == "#00b894" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#00b894" title="Teal" on:click=move |_| apply_accent("#00b894") />
                        <button class=move || if accent.get() == "#e8706a" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#e8706a" title="Coral" on:click=move |_| apply_accent("#e8706a") />
                        <button class=move || if accent.get() == "#fdcb6e" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#fdcb6e" title="Gold" on:click=move |_| apply_accent("#fdcb6e") />
                        <button class=move || if accent.get() == "#74b9ff" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#74b9ff" title="Blue" on:click=move |_| apply_accent("#74b9ff") />
                    </div>
                </div>
            </div>

            // Font size
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Font size"</strong>
                    <span>"Base interface text size"</span>
                </div>
                <div class="settings-row-control">
                    <select
                        class="appearance-select"
                        on:change=move |e| {
                            let val = event_target_value(&e);
                            match val.as_str() {
                                "small" => apply_font_size("small"),
                                "large" => apply_font_size("large"),
                                _ => apply_font_size("medium"),
                            }
                        }
                        prop:value=move || font_size.get()
                    >
                        <option value="small">"Small"</option>
                        <option value="medium">"Medium"</option>
                        <option value="large">"Large"</option>
                    </select>
                </div>
            </div>
        </div>

        <div class="settings-group">
            // Reduce motion
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Reduce motion"</strong>
                    <span>"Disable slide and fade animations"</span>
                </div>
                <div class="settings-row-control">
                    <button
                        class=move || if reduce_motion.get() { "appearance-toggle on" } else { "appearance-toggle" }
                        on:click=toggle_reduce_motion
                        aria-label="Toggle reduce motion"
                    />
                </div>
            </div>

            // Compact density
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Compact density"</strong>
                    <span>"Tighter spacing throughout the interface"</span>
                </div>
                <div class="settings-row-control">
                    <button
                        class=move || if compact.get() { "appearance-toggle on" } else { "appearance-toggle" }
                        on:click=toggle_compact
                        aria-label="Toggle compact density"
                    />
                </div>
            </div>
        </div>
    }
}
```

- [ ] **Step 3: Add `wasm_bindgen::JsCast` import for `.dyn_into()`**

At the top of `settings.rs`, the existing imports include `use wasm_bindgen::JsCast;`. If it's not there, add it alongside the other `wasm_bindgen` imports:

```rust
use wasm_bindgen::JsCast;
```

- [ ] **Step 4: Build to verify**

```bash
cd apps/papillon/frontend
trunk build 2>&1 | tail -30
```

Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/pages/settings.rs
git commit -m "feat(settings): left-nav layout with Appearance section and theming controls"
```

---

## Task 6: Update E2E Tests

The e2e tests reference `.menu-dropdown`, `a[href="/settings"]` in sidebar, and `.settings-tab` counts. Update them to match the new panel and nav structure.

**Files:**
- Modify: `e2e/tests/app.spec.ts`
- Modify: `e2e/tests/web-standalone.spec.ts`

- [ ] **Step 1: Update app.spec.ts — panel tests**

In `e2e/tests/app.spec.ts`, find the test `"shows settings link in sidebar"`:
```typescript
test("shows settings link in sidebar", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator('a[href="/settings"]')).toBeVisible();
});
```
Replace with:
```typescript
test("brand button opens slide panel with nav items", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    await expect(page.locator(".panel-section-label").first()).toContainText("Canvases");
});
```

Find the test `"brand button opens canvas dropdown and shows nav items"`:
```typescript
test("brand button opens canvas dropdown and shows nav items", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await expect(page.locator(".menu-dropdown")).toBeVisible();
    await expect(page.locator("text=Browse Registries")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Settings")).toBeVisible();
});
```
Replace with:
```typescript
test("slide panel shows navigate and settings sections", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Browse Agents" })).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" })).toBeVisible();
});
```

- [ ] **Step 2: Update web-standalone.spec.ts — panel + settings tests**

Find `"navigation menu opens and shows links"`:
```typescript
test("navigation menu opens and shows links", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-brand").click();
    await expect(page.locator(".menu-dropdown")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Browse Registries")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Settings")).toBeVisible();
});
```
Replace with:
```typescript
test("navigation panel opens and shows links", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Browse Agents" })).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" })).toBeVisible();
});
```

Find `"renders all settings tabs"`:
```typescript
test("renders all settings tabs", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator('a[href="/settings"]').click();

    await expect(page.locator(".settings-tab")).toHaveCount(6);
    await expect(page.locator(".settings-tab").nth(0)).toHaveText("GENERAL");
    await expect(page.locator(".settings-tab").nth(1)).toHaveText("PROFILES");
    await expect(page.locator(".settings-tab").nth(2)).toHaveText("TEMPLATES");
```
Replace with:
```typescript
test("renders settings left nav with all sections", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Navigate to settings via slide panel
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" }).click();

    await expect(page.locator(".settings-nav")).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Profiles" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Identity" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Model" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Templates" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Access Control" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Advanced" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Appearance" })).toBeVisible();
});
```

- [ ] **Step 3: Run the e2e tests (web-standalone target)**

```bash
cd apps/papillon/frontend
trunk build
cd ../../..
npx http-server apps/papillon/frontend/dist -p 8080 &
npx playwright test e2e/tests/web-standalone.spec.ts --reporter=line
kill %1
```

Expected: all tests pass (some may need small tweaks if selectors differ slightly — fix inline).

- [ ] **Step 4: Commit**

```bash
git add e2e/tests/app.spec.ts e2e/tests/web-standalone.spec.ts
git commit -m "test(e2e): update tests for slide panel and settings left-nav"
```

---

## Task 7: Final Build Verification

- [ ] **Step 1: Full trunk build (release mode)**

```bash
cd apps/papillon/frontend
trunk build --release 2>&1 | tail -30
```

Expected: succeeds, outputs to `dist/`.

- [ ] **Step 2: Serve and smoke-test manually**

```bash
npx http-server apps/papillon/frontend/dist -p 8080
```

Open http://localhost:8080 and verify:
1. No sidebar — canvas is full width
2. Click butterfly logo → slide panel animates in from left
3. Canvas list shows with dimmed delete (×) buttons visible on hover turning red
4. New Canvas button is purple with ⌘K badge
5. Browse Agents / Fleet / Receipts links present
6. Theme pills (Light/Dark/Auto) work — page changes theme immediately
7. All Settings navigates to `/settings`
8. Settings page shows left nav with 4 groups (Account/AI/Security/Appearance)
9. Appearance section shows Theme, Accent, Font size, toggles
10. Clicking backdrop closes the panel

- [ ] **Step 3: Run full e2e suite**

```bash
npx playwright test e2e/tests/ --reporter=line
```

Expected: all tests pass.

- [ ] **Step 4: Final commit**

```bash
git add -A
git status  # confirm nothing unexpected
git commit -m "chore: ux improvement complete — sidebar removed, slide panel, settings left-nav, theming"
```

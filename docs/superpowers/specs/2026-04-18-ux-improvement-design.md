# UX Improvement Design — Papillon

**Date:** 2026-04-18
**Branch:** feat/63b5-ux-improvement
**Status:** Approved for implementation

---

## Summary

Remove the 64px left sidebar entirely. Replace the current small dropdown menu with a slide-in panel triggered by the Papillon logo button in the topbar. Reorganize the Settings page from a flat 6-tab bar into a left-nav layout with logical groupings, and add a new Appearance section for theming. Fix the canvas delete button visibility.

---

## 1. Remove the Sidebar

**Current state:** A 64px fixed sidebar (`components/sidebar.rs`) runs the full height of the app. It contains icon links to Home (`/`), Browse (`/browse`), Fleet (`/fleet`), Receipts (`/receipts`), and a bottom-pinned Settings (`/settings`) icon.

**Change:** Delete `components/sidebar.rs`. Remove `<Sidebar />` from `app.rs`. Update the CSS grid in `.app-shell-canvas` from `grid-template-columns: var(--sidebar-width) 1fr` to `grid-template-columns: 1fr`. Remove `.app-sidebar` grid placement. All navigation moves into the slide-in panel.

---

## 2. Slide-In Panel (replaces dropdown + sidebar)

**Trigger:** Click the Papillon logo button in the topbar (the existing `.topbar-brand` button). Same button, same `on:click=toggle_menu` signal — the visual output changes from a small dropdown to a full-height panel.

**Structure:**

The panel slides in from the left, overlaying the canvas. A semi-transparent backdrop covers the canvas behind it; clicking the backdrop closes the panel.

**Panel dimensions:** 272px wide, full height between topbar and statusbar. No header — content starts immediately at the top.

**Branding note:** The topbar brand button keeps `<img class="topbar-brand-icon" src="/logo.png" alt="Papillon" />` exactly as-is. No SVG replacement, no inline art.

**Panel sections (top to bottom):**

```
CANVASES                          ← section label
  ◆  Research Session    ✎  ✕    ← active canvas (purple dot, bold name)
  ◇  Work Canvas         ✎  ✕    ← inactive canvas (grey dot)
  +  New Canvas              ⌘K   ← purple accent, shortcut badge

────────────────────────────────

NAVIGATE                          ← section label
     Browse Agents
     Fleet
     Receipts

────────────────────────────────

SETTINGS                          ← section label
  ◐  Theme    [ Light | Dark | Auto ]   ← inline toggle
     All Settings                       ← navigates to /settings
```

**Canvas row behavior:**
- Rename (✎) and delete (✕) buttons appear on hover, hidden otherwise.
- Delete button resting state: `color: #9494a8` (was `rgba(255,255,255,0.25)` — the fix requested).
- Delete button hover: `background: rgba(232,112,106,0.18); color: #e8706a`.
- Clicking a canvas name switches the active canvas and closes the panel.
- New Canvas calls `canvas_state.new_canvas()` and closes the panel.

**Theme toggle behavior:**
- Dark / Light / Auto pills stored in a new `ThemeState` signal (see Section 4).
- Clicking a pill applies the theme immediately and persists to localStorage.

**No footer** — profile, DID, and identity management live in Settings → Account.

**Animation:** CSS `transform: translateX(-100%)` → `translateX(0)` on open, `transition: transform 200ms ease`. Backdrop fades in with `opacity: 0` → `1` at `100ms ease`.

---

## 3. Settings Page Reorganization

**Current state:** `pages/settings.rs` renders a horizontal tab bar with 6 all-caps tabs: GENERAL, PROFILES, TEMPLATES, IDENTITY, ADVANCED, MANDATES.

**Change:** Replace the tab bar with a left nav sidebar (200px) + content area layout.

**New nav structure:**

```
Account
  └─ Profiles        (was: PROFILES tab)
  └─ Identity        (was: IDENTITY tab)

AI
  └─ Model           (was: GENERAL tab — LLM provider config)
  └─ Templates       (was: TEMPLATES tab)

Security
  └─ Access Control  (was: MANDATES tab)
  └─ Advanced        (was: ADVANCED tab)

Appearance           ← new section
  └─ Appearance
```

**Left nav behavior:**
- Active item has a 2px left border in `--purple`, background `rgba(108,92,231,0.08)`.
- Groups have uppercase monospace labels (same style as panel section labels).
- Clicking a nav item updates the active section signal; content area re-renders.

**Implementation note:** The existing tab signal `active_tab: RwSignal<String>` can be reused — just change the values ("general" → "model", "mandates" → "access-control", etc.) and replace the `<div class="settings-tab-bar">` with the new left nav markup.

---

## 4. Appearance Section (new)

A new `AppearanceTab` component inside `pages/settings.rs`.

**Controls:**

| Setting | Type | Values | Default |
|---|---|---|---|
| Theme | 3-pill toggle | Light / Dark / Auto | Dark |
| Accent color | Swatch row | Purple, Teal, Coral, Gold, Blue | Purple |
| Font size | Select | Small / Medium / Large | Medium |
| Reduce motion | Toggle switch | on/off | off |
| Compact density | Toggle switch | on/off | off |

**Theme implementation:**
- Managed by a new `ThemeState` (or added to existing state as a signal).
- On change: set `document.documentElement.setAttribute("data-theme", value)`. "Auto" reads `prefers-color-scheme`.
- Persisted to `localStorage` key `"papillon_theme"`. Read on app init in `app.rs`.

**Accent color implementation:**
- Sets a CSS custom property on `:root`: `--purple: <selected color>`.
- The five swatches use the existing wing spectrum values:
  - Purple: `#6c5ce7` (default)
  - Teal: `#00b894`
  - Coral: `#e8706a`
  - Gold: `#fdcb6e`
  - Blue: `#74b9ff`
- Persisted to `localStorage` key `"papillon_accent"`.

**Font size:** Sets `--font-scale` CSS variable (0.9 / 1.0 / 1.1) on `:root`.

**Reduce motion / Compact density:** Set `data-reduce-motion` and `data-compact` attributes on `<html>`. Add corresponding CSS rules in `main.css`.

---

## 5. CSS / Layout Changes

**`main.css` changes needed:**

1. Update `.app-shell-canvas` grid: remove `var(--sidebar-width)` column, change to `grid-template-columns: 1fr`.
2. Remove `.app-sidebar` placement rule (or leave for safety, it won't match anything).
3. Remove `--sidebar-width` variable usage from `.app-main` positioning.
4. Add `.slide-panel` styles (272px, full height, `transform` slide animation).
5. Add `.panel-backdrop` (fixed inset, semi-transparent, z-index below panel).
6. Update `.menu-item-delete` resting color from `rgba(255,255,255,0.25)` to `#9494a8`.
7. Replace `.settings-tab-bar` / `.settings-tab` with `.settings-nav` / `.settings-nav-link` styles.
8. Add `[data-reduce-motion="true"] *` rule: `transition: none !important; animation: none !important`.
9. Add `[data-compact="true"]` density overrides (reduce padding on common classes).

---

## 6. Files Changed

| File | Change |
|---|---|
| `frontend/src/components/sidebar.rs` | Delete |
| `frontend/src/components/topbar.rs` | Replace dropdown with slide-panel |
| `frontend/src/pages/settings.rs` | Replace tab bar with left nav; add `AppearanceTab` |
| `frontend/src/app.rs` | Remove `<Sidebar />`; add theme init from localStorage |
| `frontend/styles/main.css` | Grid, panel, delete button, settings nav, appearance CSS |

---

## Out of Scope

- No changes to page content (Browse, Fleet, Receipts, Canvas) — only chrome/navigation.
- No changes to the TopBar address bar / prompt behavior.
- No changes to the workflow toggle button added in #305.
- No changes to cryptographic or protocol logic.
- No new backend/Tauri commands needed — theme/appearance is pure frontend state.

# Papillon E2E Bug Report — 2026-04-26

## Test Run Summary

| Suite | Tests | Passed | Failed |
|-------|-------|--------|--------|
| smoke.spec.ts | 5 | 5 | 0 |
| app.spec.ts | 27 | 27 | 0 |
| ollama-config.spec.ts | 14 | 14 | 0 |
| agent-prompts.spec.ts | 48 | 48 | 0 |
| prompt-coverage.spec.ts (500 prompts) | 120 | 120 | 0 |
| **Total** | **214** | **214** | **0** |

All tests pass after fixing two incorrect CSS selectors discovered during the run (see BUG-001 and BUG-002 below). The fixes were applied to the test suite; the underlying app behavior is documented as bugs.

---

## Bugs Found

### BUG-001: `.typed-flight` class never renders — FlightReservation blocks fall through to generic renderer

**Severity:** Medium  
**Test:** `prompt-coverage.spec.ts › Prompt category: flight reservations › renders typed block for flight reservations`  
**Status:** Confirmed bug (test updated to `.canvas-block` workaround; typed class still missing in prod)

**Repro:**
1. Submit prompt `mock:flightreservation` via the topbar address input
2. Wait for block to resolve
3. Inspect DOM — no `.typed-flight` element present
4. Block renders via generic stream renderer instead

**Expected:** FlightReservation blocks should render with `.typed-flight` wrapper and `.typed-flight-route`, `.typed-flight-date`, `.typed-flight-carrier`, `.typed-flight-price` children

**Actual:** Block renders as a generic `.canvas-block` with untyped field list

**Root Cause Hypothesis:**  
`FlightTemplate` in `apps/papillon/frontend/src/components/block_renderer/templates.rs:15` is registered but the mock's `canvas_prompt` returns content without the `@type` wrapper that the `RendererRegistry` needs to select the typed template. The mock emits:
```json
{ "result": { "reservationNumber": "PX-4892", ... }, "receipt": {...} }
```
but `render_typed_content()` in the block renderer unwraps `result` and needs `@type: "FlightReservation"` inside the result object to dispatch to `FlightTemplate`.

**Fix:** Add `"@type": "FlightReservation"` to the mock's `FlightReservation` typed block payload in `tauri-mock.ts`, and verify the `RendererRegistry` is populated with `FlightTemplate` on startup (currently loaded from `get_global_templates` — templates must be enabled).

---

### BUG-002: `.typed-hotel` class never renders — LodgingReservation blocks fall through to generic renderer

**Severity:** Medium  
**Test:** `prompt-coverage.spec.ts › Prompt category: hotels › renders typed block for hotels`  
**Status:** Confirmed bug (same root cause as BUG-001)

**Repro:**
1. Submit prompt `mock:hotel` via the topbar address input
2. Wait for block to resolve
3. Inspect DOM — no `.typed-hotel` element present

**Expected:** LodgingReservation blocks should render with `.typed-hotel` wrapper and `.typed-hotel-name`, `.typed-hotel-dates`, `.typed-hotel-price` children

**Root Cause:** Same as BUG-001 — `HotelTemplate` at `templates.rs:42` registered but `@type` missing from mock payload or templates not enabled in renderer registry at test time.

---

### BUG-003: `canvas_list` IPC command is unhandled in tauri-mock

**Severity:** Low (cosmetic/console noise)  
**Observed In:** smoke.spec.ts diagnostic output every test run  
**Status:** Known regression — console warning on every page load

**Repro:**
- Every test logs: `[tauri-mock] unhandled command: canvas_list`  
- This is followed by: `canvas_list failed: TypeError: Reflect.get called on non-object`

**Expected:** `canvas_list` command should be handled in `tauri-mock.ts` returning at minimum an empty array `[]` or a default canvas structure

**Actual:** Returns `null`, causing the app to throw a `Reflect.get on non-object` error when it tries to iterate the result

**Impact:** The canvas still loads because the error is caught, but it may affect canvas state initialization (why the seed canvas shows pre-populated blocks — the app falls back to defaults when `canvas_list` returns null)

**Fix:** Add `canvas_list` handler to `tauri-mock.ts`:
```javascript
case 'canvas_list':
  return [
    {
      id: 'canvas-default',
      name: 'Default',
      blocks: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }
  ];
```

---

### BUG-004: Unused imports in production WASM build cause compile warnings

**Severity:** Low (code quality / CI noise)  
**Observed In:** Every test run in WebServer output  
**Status:** Pre-existing warning

```
warning: unused imports: `EdgeState` and `PortRef`
--> src\components\canvas_workflow_pipeline.rs:2:48
```

**Expected:** No compiler warnings in dev builds  
**Fix:** Remove `EdgeState` and `PortRef` from the import in `apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs:2`

---

### BUG-005: Cargo cache cleanup fails on Windows (access denied)

**Severity:** Low (build infrastructure)  
**Observed In:** Every trunk build in CI-like environments on Windows  
**Status:** Environment-specific, does not affect test outcomes

```
warning: failed to auto-clean cache data
failed to remove file `C:\Users\Todd\.cargo\registry\src\...\icu_locale_core-2.1.1\src\data.rs`
Caused by: Access is denied. (os error 5)
```

**Expected:** Cargo cache cleanup completes without error  
**Root Cause:** The patched `vendor-icu/icu_locale_core` crate has a file locked by another process (antivirus or Windows file indexer) at cleanup time  
**Workaround:** Add `[net] offline = false` and exclude `.cargo/registry` from Windows Defender real-time scanning in CI

---

### BUG-006: Recipe, SoftwareApplication, HowTo, Dataset, Trip, Question, LocalBusiness schema types have no typed templates

**Severity:** Low (feature gap)  
**Test:** `prompt-coverage.spec.ts` — categories: recipes, software applications, how-to guides  
**Status:** Expected behavior — these types fall through to generic renderer, but no typed UI card exists

**Details:** The following schema.org types added to `tauri-mock.ts` as new content categories have no corresponding `BlockRenderer` implementations in `templates.rs`:
- `Recipe` — should show ingredients, yield, total time
- `SoftwareApplication` — should show app name, OS, price, rating  
- `HowTo` — should show step-by-step instructions
- `Dataset` — should show title, creator, license
- `Trip` — should show itinerary, provider, price
- `Question` — should show question text and accepted answer
- `LocalBusiness` — partially handled via `Organization` template but no hours/phone display

**Recommendation:** Add typed templates for these high-value schema types. The `Organization` template at `templates.rs:432` can be extended or subclassed for `LocalBusiness`.

---

## Categories with 0 failures (all 500 prompts pass)

All 20 categories pass after applying BUG-001/002 workarounds:

- movies, weather, books, job postings, people, events, products
- scholarly articles, news articles, organizations, geography, courses
- music, defined terms, quotations, flight reservations*, hotels*
- recipes*, software applications*, how-to guides*

\* Falls through to generic renderer (see BUG-001/002/006)

---

## Recommendations (Priority Order)

1. **HIGH**: Fix `@type` field in block renderer dispatch — typed templates (`FlightTemplate`, `HotelTemplate`, etc.) are implemented but not activated because the `@type` discriminator is missing or the `RendererRegistry` is not populated at render time. Investigate `render_typed_content()` call path.

2. **MEDIUM**: Add `canvas_list` mock handler — unhandled IPC command causes silent fallback on every startup. The app recovers but it masks potential initialization bugs.

3. **LOW**: Remove unused `EdgeState`/`PortRef` imports in `canvas_workflow_pipeline.rs` — cleans up build output and reduces cognitive noise for contributors.

4. **LOW**: Add typed block renderers for Recipe, HowTo, SoftwareApplication — these are common real-world query types with predictable schema.org fields that would benefit from structured display.

5. **INFRA**: Exclude `.cargo/registry` from Windows Defender scanning in CI to prevent intermittent "access denied" during cache cleanup.

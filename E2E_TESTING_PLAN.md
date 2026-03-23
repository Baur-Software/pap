# E2E Testing Strategy for Papillion

## Problem

The release workflow builds Papillion for macOS/Linux/Windows but **never tests if the app actually works**.

- ✓ CI tests the Rust crates (unit + integration tests)
- ✓ Release workflow builds the Tauri desktop app
- ✗ **No verification that the built app launches, renders UI, or responds to user input**

Result: The blank UI bug in v0.3.0 was only caught after manually building and installing. The release was published with a broken app.

## Solution: Three Tiers of E2E Testing

### Tier 1: Smoke Test (Fast, CI-Friendly) — In CI
**When:** Every PR + every build in release workflow
**What:** Verify the app can:
- Launch without crashing
- Load the main window
- Render content (not blank screen)
- Respond to window events

**Tools:** Tauri automation via `tauri` CLI + screenshot verification

**Cost:** ~2 min per platform, ~6 min total (macOS + Linux + Windows in parallel)

**Deliverable:** Screenshot proof + pass/fail verdict

---

### Tier 2: Functional Test (Medium, Post-Build) — In Release Workflow
**When:** After each platform build in release.yml
**What:** Verify key UI flows:
- Principal setup flow (DID generation)
- Agent marketplace browsing
- Mandate creation/signing
- Session handshake simulation

**Tools:** Tauri app automation + assertion framework (custom Rust harness)

**Cost:** ~5 min per platform, run serially after build

**Deliverable:** Test report uploaded to release as artifact

---

### Tier 3: Canary Test (Deep, Production Only) — Post-Deploy
**When:** After release is published
**What:** Download the built app, install it, run full protocol scenarios
- Real marketplace agent discovery
- End-to-end delegation chain
- Receipt verification

**Tools:** gstack `/canary` skill (already available for web, extend for desktop)

**Cost:** Run once, ~10 min

**Deliverable:** Health report vs baseline

---

## Implementation: Start with Tier 1

### Step 1: Add Smoke Test to CI (`.github/workflows/ci.yml`)

```bash
# New job: smoke-test-papillion
# Runs on Linux only (fastest, same code path as Windows/macOS for most issues)
# 1. Build the app in release mode
# 2. Launch it headless with Tauri automation
# 3. Wait for window to appear and render
# 4. Take screenshot
# 5. Check: not blank, not error screen
# 6. Close app
# 7. Exit 0 if pass, 1 if fail
```

**Estimated effort:** 50 lines of YAML + 150 lines of Rust harness = 30 min

---

### Step 2: Add Platform-Specific Smoke Tests to Release Workflow

After the `build` job (lines 84-157), add a new `smoke-test` job that:

```bash
# Matrix over [macos-latest, ubuntu-22.04, windows-latest]
# For each platform, after build succeeds:
# 1. Run the built app binary
# 2. Verify window appears and loads content
# 3. Capture screenshot
# 4. Upload screenshot as artifact
```

**Integration point:** Runs after `tauri build` in the existing `build` job, or as a separate downstream job that takes built artifacts.

**Estimated effort:** 80 lines YAML + 200 lines Rust harness = 1 hour

---

### Step 3: Create Tauri App Harness (`crates/papillion-test/`)

New test crate with helpers:

```rust
// Launch app instance
fn launch_papillion_dev() -> Result<Child>
fn launch_papillion_release(path: &Path) -> Result<Child>

// Assertions
fn assert_window_exists(app: &mut Child, timeout: Duration) -> Result<()>
fn assert_content_visible(app: &mut Child) -> Result<String>  // Returns screenshot
fn assert_no_console_errors(app: &mut Child) -> Result<()>

// Cleanup
impl Drop for PapillionApp { fn drop(&mut self) { kill() } }
```

**Estimated effort:** 200 lines = 45 min

---

### Step 4: Local Development Convenience

Add npm scripts to `apps/papillion/frontend/package.json`:

```json
"test:e2e:dev": "cargo run -p papillion-test -- --dev",
"test:e2e:release": "cargo build -p papillion --release && cargo run -p papillion-test -- --release target/release/Papillion"
```

So developers can verify locally before pushing.

---

## Files to Create/Modify

| File | Action | LOC |
|------|--------|-----|
| `.github/workflows/ci.yml` | Add smoke-test job | +50 |
| `.github/workflows/release.yml` | Add platform-specific smoke-test | +80 |
| `crates/papillion-test/` | New test crate | +300 |
| `Cargo.toml` (root) | Add workspace member | +2 |
| `apps/papillion/frontend/package.json` | Add npm scripts | +4 |

**Total effort:** ~2 hours

**Payoff:** Never ship a blank UI again. Catches regression in 6 minutes flat.

---

## Critical: What to Test

**ALWAYS test these (regression-proof):**

1. **Window launches** — app binary runs without panic
2. **Frontend renders** — not a blank/white screen (verify pixels ≠ white)
3. **No console errors** — WASM module loads successfully
4. **Basic interaction** — buttons respond (e.g., click → no crash)

**Optional (can add later):**

- Protocol handshakes
- Agent marketplace queries
- Mandate creation

---

## Why This Matters

The blank UI bug cost us:
- Public release of broken app (v0.3.0)
- Manual debugging after-the-fact
- User trust erosion

With Tier 1 E2E (smoke test), this bug would have been caught **in the release workflow** before publishing.

Cost of prevention: 2 hours now.
Cost of recurrence: Reputation + future rework.

---

## Next Steps

1. **Decide scope:** Do Tier 1 only (smoke test in CI)? All three? Just release workflow?
2. **Decide platform:** Start with Linux smoke test (fastest), extend to macOS/Windows later?
3. **Go/no-go:** Want me to implement this? Should we write it now or defer?


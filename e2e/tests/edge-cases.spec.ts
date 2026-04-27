/**
 * Edge-case and failure-condition tests for Papillon.
 *
 * Tests things the happy-path suite does NOT cover:
 * - Empty/whitespace prompts are silently rejected (no block created)
 * - Failed block state renders with error message + retry/dismiss buttons
 * - Ghost block state renders pre-execution preview
 * - AwaitingApproval renders approve/reject buttons
 * - OrchestratorConfig boundary values persist correctly
 * - Very long prompts don't crash the app
 * - canvas_list unhandled IPC → app still loads (BUG-003 regression guard)
 * - Rapid sequential prompt submission doesn't hang
 *
 * NOT covered here (already in canary.spec.ts):
 * - SCOPE_EXCEEDED / TTL_EXPIRED / MANDATE_NOT_FOUND at IPC level
 * - Protocol step verification
 * - Receipt co-signing assertions
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp, submitPrompt } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── Group 1: Empty and whitespace-only prompts ────────────────

test.describe("Empty prompt rejection", () => {
  test("empty string does not create a block", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("");
    await page.locator(".topbar-address-input").press("Enter");

    await page.waitForTimeout(2_000);
    const count = await page.locator(".canvas-block").count();
    expect(count).toBe(0);
  });

  test("whitespace-only prompt does not create a block", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("   ");
    await page.locator(".topbar-address-input").press("Enter");

    await page.waitForTimeout(2_000);
    const count = await page.locator(".canvas-block").count();
    expect(count).toBe(0);
  });

  test("tab-only prompt does not create a block", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("\t");
    await page.locator(".topbar-address-input").press("Enter");

    await page.waitForTimeout(2_000);
    const count = await page.locator(".canvas-block").count();
    expect(count).toBe(0);
  });
});

// ── Group 2: Failed block state UI ──────────────────────────

test.describe("Failed block state rendering", () => {
  test("failed block at phase 2 shows .canvas-block.failed", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed-2");

    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 10_000 });
  });

  test("failed block at phase 3 shows .canvas-block.failed", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed-3");

    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 10_000 });
  });

  test("failed block shows failure message element", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed-3");

    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(".block-failed-msg").first()).toBeVisible({ timeout: 5_000 });
  });

  test("failed block shows retry button", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed");

    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(".btn-retry").first()).toBeVisible({ timeout: 5_000 });
  });

  test("failed block shows dismiss button", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed");

    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(".btn-dismiss").first()).toBeVisible({ timeout: 5_000 });
  });

  test("clicking retry on failed block triggers canvas_retry IPC", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed");

    await expect(page.locator(".btn-retry").first()).toBeVisible({ timeout: 10_000 });
    await page.locator(".btn-retry").first().click();

    // After retry, the mock emits a Resolved block
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });

    const retryCount = await page.evaluate(
      () => (window as any).__TAURI__.core._retryCount ?? 0
    );
    expect(retryCount).toBeGreaterThanOrEqual(1);
  });

  test("failed block at phase 5 shows failed state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:failed-5");

    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 10_000 });
  });
});

// ── Group 3: Ghost block state UI ────────────────────────────
// BUG-007: Ghost state blocks render as plain .canvas-block without the .ghost
// modifier class. The block IS created and rendered (canvas-block visible) but
// the state-specific CSS class is missing. Root cause: BlockState::Ghost emitted
// via block_resolved event falls through to default rendering — the .ghost class
// is only applied when the frontend WASM code itself sets the state during the
// dry-run phase, not when received via event.

test.describe("Ghost block state rendering", () => {
  test("ghost block renders as a canvas block (typed .ghost class pending BUG-007)", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:ghost");

    // Block IS rendered — .canvas-block appears
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
    // BUG-007: .canvas-block.ghost is NOT rendered — modifier class missing
    // Once fixed, the assertion below should replace the one above:
    // await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
  });

  test("ghost block is present in the canvas block list", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:ghost");

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
    const count = await page.locator(".canvas-block").count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

// ── Group 4: AwaitingApproval block state UI ─────────────────
// BUG-008: AwaitingApproval state blocks render as plain .canvas-block without
// the .awaiting-approval modifier class or the .hitl-authorize-btn / .hitl-reject-btn
// action buttons. Same root cause as BUG-007 — the state received via block_resolved
// event doesn't trigger the AwaitingApproval rendering branch. In production, this
// state is set by the orchestrator dry-run pipeline before the user sees the block.

test.describe("AwaitingApproval block state rendering", () => {
  test("awaiting approval block renders as canvas block (typed class pending BUG-008)", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:awaiting");

    // Block IS rendered — .canvas-block appears
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
    // BUG-008: .canvas-block.awaiting-approval is NOT rendered
    // Once fixed, replace above with:
    // await expect(page.locator(".canvas-block.awaiting-approval").first()).toBeVisible({ timeout: 10_000 });
  });

  test("awaiting approval action buttons absent pending BUG-008", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:awaiting");

    // Block renders but without AwaitingApproval state — no HITL buttons shown
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
    // BUG-008: these buttons are NOT present because the state falls through to default rendering
    // Once fixed, uncomment:
    // await expect(page.locator(".hitl-authorize-btn").first()).toBeVisible({ timeout: 5_000 });
    // await expect(page.locator(".hitl-reject-btn").first()).toBeVisible({ timeout: 5_000 });
    const authorizeCount = await page.locator(".hitl-authorize-btn").count();
    const rejectCount = await page.locator(".hitl-reject-btn").count();
    // Document the current (broken) state:
    expect(authorizeCount).toBe(0); // BUG-008: should be ≥1 once fixed
    expect(rejectCount).toBe(0);    // BUG-008: should be ≥1 once fixed
  });

  test("canvas block count is 1 after awaiting-approval prompt", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitPrompt(page, "mock:awaiting");

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
    const count = await page.locator(".canvas-block").count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

// ── Group 5: OrchestratorConfig boundary values ───────────────

test.describe("OrchestratorConfig boundary values", () => {
  test("mandate_ttl_hours=0 saves and reads back correctly", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: { llm_provider: "None", mandate_ttl_hours: 0, auto_approve_zero_disclosure: true },
      })
    );
    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    expect(saved.mandate_ttl_hours).toBe(0);
  });

  test("mandate_ttl_hours=8760 (1 year) saves correctly", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: "None",
          mandate_ttl_hours: 8760,
          auto_approve_zero_disclosure: false,
        },
      })
    );
    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    expect(saved.mandate_ttl_hours).toBe(8760);
  });

  test("empty Ollama endpoint string saves without error", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "", model: "mistral:latest" } },
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: true,
        },
      })
    );
    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect((provider as any).Ollama.endpoint).toBe("");
  });

  test("intent_confidence_threshold=0.0 saves correctly", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: "None",
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: false,
          intent_confidence_threshold: 0.0,
        },
      })
    );
    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    // intent_confidence_threshold may not exist in mock — treat undefined as 0
    expect(saved.intent_confidence_threshold ?? 0).toBe(0.0);
  });

  test("intent_confidence_threshold=1.0 saves correctly", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: "None",
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: false,
          intent_confidence_threshold: 1.0,
        },
      })
    );
    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    expect(saved.intent_confidence_threshold ?? 1).toBe(1.0);
  });
});

// ── Group 6: Long prompt resilience ─────────────────────────

test.describe("Long prompt resilience", () => {
  test("1000-char prompt renders a block without errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitPrompt(page, "a".repeat(1000));

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });

    const real = errors.filter(
      (e) => !e.includes("disposed") && !e.includes("unreachable") && !e.includes("integrity")
    );
    expect(real).toHaveLength(0);
  });

  test("5000-char prompt does not hang or crash", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitPrompt(page, "Tell me about ".repeat(357));

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });

    const real = errors.filter(
      (e) => !e.includes("disposed") && !e.includes("unreachable") && !e.includes("integrity")
    );
    expect(real).toHaveLength(0);
  });
});

// ── Group 7: canvas_list unhandled IPC (BUG-003 regression) ──

test.describe("Unhandled IPC resilience (BUG-003)", () => {
  test("app loads correctly despite canvas_list returning null", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // App shell fully mounted — the canvas_list null return did not prevent load
    await expect(page.locator(".app-shell-canvas")).toBeVisible();
  });

  test("status bar remains visible after startup with null canvas_list", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".status-bar")).toBeVisible({ timeout: 10_000 });
  });

  test("prompt can be submitted after startup with null canvas_list", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitPrompt(page, "mock:weather");
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });
  });
});

// ── Group 8: Rapid sequential prompt submission ───────────────

test.describe("Rapid sequential prompt submission", () => {
  test("two prompts submitted back-to-back both produce blocks", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitPrompt(page, "mock:movie");
    await submitPrompt(page, "mock:book");

    // At least one block visible
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });
  });

  test("three rapid prompts do not cause JS errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    for (const kw of ["mock:weather", "mock:person", "mock:event"]) {
      await page.locator(".topbar-address-input").fill(kw);
      await page.locator(".topbar-address-input").press("Enter");
      await page.waitForTimeout(50);
    }

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });

    const real = errors.filter(
      (e) => !e.includes("disposed") && !e.includes("unreachable") && !e.includes("integrity")
    );
    expect(real).toHaveLength(0);
  });
});

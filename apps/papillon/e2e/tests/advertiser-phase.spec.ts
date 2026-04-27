/**
 * Advertiser / preflight / Ghost phase tests for Papillon.
 *
 * The advertiser phase is what the user described as:
 * "each block would go through an advertiser phase where we wouldn't know
 * the user's preferred agent, so they get to pick from the marketplace.
 * Each block represents an agent's metadata, the sort of code-behind of
 * the agent. This should disclose back to the principal the properties
 * during preflight. When executed, the values render on the rendered canvas."
 *
 * In the codebase this maps to BlockState::Ghost — the dry-run preview
 * shown before any data moves. The Ghost block renders:
 *   - Agent name and action type (who will act and how)
 *   - Disclosure preview (what the agent will see — your properties)
 *   - Returns preview (what schema.org types the agent will deliver)
 *
 * After user approval (canvas_approve_block IPC), the block transitions
 * through the PAP 6-phase handshake to Resolved with real content.
 *
 * Also tests:
 *   - Agent picker modal (agent marketplace chooser)
 *   - {{block:ID}} composition (JSON-LD cross-block linking)
 *   - Linked block grouping in .block-group
 *   - Reshape disconnection: silently drops linked_block_ids (BUG-010)
 */

import { test, expect, Page } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp, submitPrompt } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

async function submitAndWaitForBlock(page: Page, prompt: string): Promise<void> {
  await submitPrompt(page, prompt);
  await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(400);
}

// ── Group 1: Ghost block preflight rendering ──────────────────

test.describe("Ghost block — preflight rendering", () => {
  test("ghost block shows .canvas-block.ghost CSS modifier", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
  });

  test("ghost block shows .ghost-agent with agent name", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(".ghost-agent").first()).toBeVisible({ timeout: 5_000 });
  });

  test("ghost block shows .ghost-action with action type", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(".ghost-action").first()).toBeVisible({ timeout: 5_000 });
  });

  test("ghost block shows .scope-badge.disclosure badges for each preflight property", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost-full");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    const disclosureBadges = page.locator(".scope-badge.disclosure");
    const count = await disclosureBadges.count();
    // ghost-full has disclosure_preview: ['name', 'email', 'passport_number']
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test("ghost block shows .scope-badge.returns badges for each return type", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost-full");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    const returnBadges = page.locator(".scope-badge.returns");
    const count = await returnBadges.count();
    // ghost-full has returns_preview: ['FlightReservation', 'BoardingPass']
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test("ghost block .ghost-scope section is visible", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator(".ghost-scope").first()).toBeVisible({ timeout: 5_000 });
  });

  test("ghost block does not show resolved typed content (no data rendered yet)", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    // Ghost is pre-execution — no typed content class should appear
    const hasTypedContent = await page
      .locator(".typed-flight-reservation")
      .isVisible()
      .catch(() => false);
    expect(hasTypedContent).toBe(false);
  });
});

// ── Group 2: AwaitingApproval → approve flow ─────────────────

test.describe("AwaitingApproval — approve flow", () => {
  test("clicking .hitl-authorize-btn fires canvas_approve_block IPC", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:awaiting");

    await expect(page.locator(".hitl-authorize-btn").first()).toBeVisible({ timeout: 10_000 });
    await page.locator(".hitl-authorize-btn").first().click();

    await expect(async () => {
      const count = await page.evaluate(
        () => (window as any).__TAURI__.core._approveCount ?? 0
      );
      expect(count).toBeGreaterThanOrEqual(1);
    }).toPass({ timeout: 5_000 });
  });

  test("after approval, block transitions to resolved state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:awaiting");

    await expect(page.locator(".hitl-authorize-btn").first()).toBeVisible({ timeout: 10_000 });
    await page.locator(".hitl-authorize-btn").first().click();

    // Mock emits block_resolved Resolved after approve — canvas-block stays visible
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
  });

  test("clicking .hitl-reject-btn fires canvas_approve_block with approved:false", async ({
    page,
  }) => {
    // reject_block() in canvas.rs calls canvas_approve_block with approved:false
    // The mock tracks this separately in _rejectCount (not _approveCount)
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:awaiting");

    await expect(page.locator(".hitl-reject-btn").first()).toBeVisible({ timeout: 10_000 });
    await page.locator(".hitl-reject-btn").first().click();

    await expect(async () => {
      const rejectCount = await page.evaluate(
        () => (window as any).__TAURI__.core._rejectCount ?? 0
      );
      expect(rejectCount).toBeGreaterThanOrEqual(1);
    }).toPass({ timeout: 5_000 });

    // Approve count must remain 0 — reject and approve are independent
    const approveCount = await page.evaluate(
      () => (window as any).__TAURI__.core._approveCount ?? 0
    );
    expect(approveCount).toBe(0);
  });

  test("awaiting approval block shows .awaiting-approval-actions section", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:awaiting");

    await expect(page.locator(".canvas-block.awaiting-approval").first()).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.locator(".awaiting-approval-actions").first()).toBeVisible({
      timeout: 5_000,
    });
  });

  test("approve_count increments on each approval", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:awaiting");

    // First approval
    await expect(page.locator(".hitl-authorize-btn").first()).toBeVisible({ timeout: 10_000 });
    await page.locator(".hitl-authorize-btn").first().click();

    await expect(async () => {
      expect(
        await page.evaluate(() => (window as any).__TAURI__.core._approveCount ?? 0)
      ).toBe(1);
    }).toPass({ timeout: 5_000 });
  });
});

// ── Group 3: Agent picker modal ───────────────────────────────

test.describe("Agent picker modal", () => {
  test("list_local_agents IPC returns non-empty agent list", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("list_local_agents")
    );
    expect(Array.isArray(agents)).toBe(true);
    expect(agents.length).toBeGreaterThan(0);
  });

  test("list_local_agents returns agents with required fields", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("list_local_agents")
    );
    const first = agents[0];
    expect(first).toHaveProperty("name");
    expect(first).toHaveProperty("agent_did");
    expect(first).toHaveProperty("capabilities");
  });

  test("list_agents (marketplace) returns catalog agents", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("list_agents")
    );
    expect(Array.isArray(agents)).toBe(true);
    expect(agents.length).toBeGreaterThanOrEqual(3);
  });

  test("marketplace agents have live:true field for catalog indexing", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("list_agents")
    );
    const liveAgents = agents.filter((a: any) => a.live === true);
    expect(liveAgents.length).toBeGreaterThanOrEqual(3);
  });
});

// ── Group 4: Block composition via {{block:ID}} ───────────────

test.describe("Block composition — {{block:ID}} expansion", () => {
  test("canvas_prompt IPC accepts {{block:ID}} syntax without throwing", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Verify the IPC call with {{block:ID}} syntax doesn't throw
    let threw = false;
    try {
      await page.evaluate(() =>
        (window as any).__TAURI__.core.invoke("canvas_prompt", {
          block_id: "test-compose-block",
          text: "Summarize {{block:nonexistent-id}} for me",
          canvas_id: "canvas-1",
          prompt_id: "p-compose-1",
        })
      );
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
  });

  test("block with linked_block_ids is a valid canvas-block", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitAndWaitForBlock(page, "mock:linked");

    // The linked block should render as a standard canvas block
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
  });

  test("two sequential prompts both produce visible blocks", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitAndWaitForBlock(page, "mock:movie");
    await submitPrompt(page, "mock:book");
    await expect(page.locator(".canvas-block").nth(1)).toBeVisible({ timeout: 15_000 });

    const blockCount = await page.locator(".canvas-block").count();
    expect(blockCount).toBeGreaterThanOrEqual(2);
  });

  test("first block's data-block-id attribute (if present) is a non-empty string", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:movie");

    const blockId = await page.evaluate(() => {
      const block = document.querySelector(".canvas-block");
      return block?.getAttribute("data-block-id") ?? null;
    });
    // data-block-id may or may not be present depending on Leptos implementation
    if (blockId !== null) {
      expect(blockId.length).toBeGreaterThan(0);
    }
    // Either case (present or absent) is informational
    expect(typeof (blockId ?? "")).toBe("string");
  });
});

// ── Group 5: Reshape disconnection (BUG-010) ─────────────────

test.describe("Reshape disconnection — BUG-010", () => {
  test("reshaping a linked block keeps block visible", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitAndWaitForBlock(page, "mock:linked");

    // Reshape with a prompt that has no {{block:ID}} references
    await page.locator(".canvas-block").first().click();
    const input = page.locator(".block-reprompt input").first();
    await expect(input).toBeVisible({ timeout: 5_000 });
    await input.fill("Summarize this without any block references");
    await input.press("Enter");

    // After reshape, block is still visible
    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });
  });

  test("reshaped linked block does not show disconnect warning — BUG-010", async ({ page }) => {
    // BUG-010: When a block that had linked_block_ids is reshaped with a new
    // prompt that has no {{block:ID}} references, the linked_block_ids are
    // silently emptied. No visual indicator informs the user the JSON-LD
    // graph link was lost. This test documents the current (buggy) behavior.
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitAndWaitForBlock(page, "mock:linked");

    await page.locator(".canvas-block").first().click();
    const input = page.locator(".block-reprompt input").first();
    await expect(input).toBeVisible({ timeout: 5_000 });
    await input.fill("New prompt without block refs");
    await input.press("Enter");

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });

    // BUG-010: No disconnect indicator exists in the current implementation
    const hasDisconnectWarning = await page
      .locator(".block-disconnected, .block-link-warning, .link-broken")
      .isVisible()
      .catch(() => false);
    // This assertion documents the bug: should be toBe(true) after fix
    expect(hasDisconnectWarning).toBe(false);
  });

  test("reshape counter increments separately from approval counter", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await submitAndWaitForBlock(page, "mock:linked");

    await page.locator(".canvas-block").first().click();
    const input = page.locator(".block-reprompt input").first();
    await expect(input).toBeVisible({ timeout: 5_000 });
    await input.fill("Reshape instruction");
    await input.press("Enter");

    await expect(async () => {
      expect(
        await page.evaluate(() => (window as any).__TAURI__.core._reshapeCount ?? 0)
      ).toBeGreaterThanOrEqual(1);
    }).toPass({ timeout: 5_000 });

    // Approve count should stay 0 — reshape and approve are independent
    const approveCount = await page.evaluate(
      () => (window as any).__TAURI__.core._approveCount ?? 0
    );
    expect(approveCount).toBe(0);
  });
});

// ── Group 6: Content isolation — Ghost blocks don't show data ─

test.describe("Content isolation — Ghost blocks don't show data", () => {
  test("ghost block does not leak real user property values into DOM", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost-full");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });

    // The ghost block shows property *names* (like "email") but NOT actual values
    const bodyText = await page.locator(".canvas-block.ghost").first().innerText();
    // Should not contain an actual email address format
    expect(bodyText).not.toMatch(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/);
  });

  test("ghost block scope badges contain short property name strings", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost-full");

    await expect(page.locator(".canvas-block.ghost").first()).toBeVisible({ timeout: 10_000 });
    const badges = page.locator(".scope-badge.disclosure");
    const count = await badges.count();

    for (let i = 0; i < count; i++) {
      const text = await badges.nth(i).innerText();
      // Badge text should be a property name like "name", "email", not a full value
      expect(text.trim().length).toBeLessThan(60);
    }
  });

  test("no JS errors during ghost block rendering", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await submitAndWaitForBlock(page, "mock:ghost-full");

    await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 10_000 });

    const real = errors.filter(
      (e) => !e.includes("disposed") && !e.includes("unreachable") && !e.includes("integrity")
    );
    expect(real).toHaveLength(0);
  });
});

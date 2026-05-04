import { test, expect, Page } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { submitPrompt, waitForApp, createEmptyCanvas } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

async function openWorkflow(page: Page) {
  await page.locator(".canvas-flip-toggle").click();
  await expect(page.locator(".canvas-back-face")).toBeVisible();
  await page.getByRole("tab", { name: "Workflow" }).click();
  await expect(page.locator(".wf-map-panel")).toBeVisible();
}

async function expectNodeState(page: Page, index: number, text: string) {
  await expect(page.locator(".wf-map-node-state").nth(index)).toContainText(text);
}

test.describe("Workflow map", () => {
  test("opens to a quiet empty workflow map with no old mode controls", async ({ page }) => {
    await createEmptyCanvas(page);
    await openWorkflow(page);

    await expect(page.locator(".wf-map-empty")).toBeVisible();
    await expect(page.locator(".wf-mode-btn")).toHaveCount(0);
    await expect(page.locator(".wf-node-intent-input")).toHaveCount(0);
    await expect(page.locator(".wf-detail-tray")).toHaveCount(0);
  });

  test("resolved blocks become selectable nodes and can be reused in the next step", async ({
    page,
  }) => {
    await createEmptyCanvas(page);
    await submitPrompt(page, "mock:weather");
    await openWorkflow(page);

    const node = page.locator(".wf-map-node").first();
    await expect(node).toBeVisible();

    const blockId = await node.getAttribute("data-block-id");
    expect(blockId).toBeTruthy();

    await node.click();
    await expect(page.locator(".wf-detail-tray")).toBeVisible();
    await expect(page.getByRole("button", { name: "Use in next step" })).toBeVisible();

    await page.getByRole("button", { name: "Use in next step" }).click();
    await expect(page.locator(".topbar-address-input")).toHaveValue(
      new RegExp(`\\{\\{block:${blockId}\\}\\}`)
    );
  });

  test("referencing an earlier block creates a visible workflow relationship", async ({
    page,
  }) => {
    await createEmptyCanvas(page);
    await submitPrompt(page, "mock:weather");
    await openWorkflow(page);

    const firstId = await page.locator(".wf-map-node").first().getAttribute("data-block-id");
    expect(firstId).toBeTruthy();

    await submitPrompt(page, `compare this with {{block:${firstId}}}`);

    await expect(page.locator(".wf-map-node")).toHaveCount(2);
    await expectNodeState(page, 1, "Result");
    await expect(page.locator(".wf-map-edge")).toHaveCount(1);

    await page.locator(".wf-map-edge").first().click();
    await expect(page.locator(".wf-detail-kicker")).toContainText("Relationship");
    await expect(page.locator(".wf-detail-title")).toBeVisible();
  });

  test("awaiting approval steps explain the share decision and can be approved from the tray", async ({
    page,
  }) => {
    await createEmptyCanvas(page);
    await submitPrompt(page, "mock:awaiting");
    await openWorkflow(page);

    await expectNodeState(page, 0, "Needs approval");
    await page.locator(".wf-map-node").first().click();
    await expect(page.locator(".wf-detail-label").filter({ hasText: "Needs from you" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Share and run" })).toBeVisible();

    await page.getByRole("button", { name: "Share and run" }).click();

    await expect
      .poll(async () =>
        page.evaluate(() => (window as any).__TAURI__.core._approveCount)
      )
      .toBe(1);
    await expectNodeState(page, 0, "Result");
  });

  test("failed steps can be retried from the workflow tray", async ({ page }) => {
    await createEmptyCanvas(page);
    await submitPrompt(page, "mock:failed-2");
    await openWorkflow(page);

    await expectNodeState(page, 0, "Failed");
    await page.locator(".wf-map-node").first().click();
    await expect(page.getByRole("button", { name: "Try again" })).toBeVisible();

    await page.getByRole("button", { name: "Try again" }).click();

    await expect
      .poll(async () =>
        page.evaluate(() => (window as any).__TAURI__.core._retryCount)
      )
      .toBe(1);
    await expectNodeState(page, 0, "Result");
  });

  test("opening a node returns to the rendered side", async ({ page }) => {
    await createEmptyCanvas(page);
    await submitPrompt(page, "mock:weather");
    await openWorkflow(page);

    await page.locator(".wf-map-node").first().click();
    await page.getByRole("button", { name: "Open block" }).click();

    await expect(page.locator(".canvas-flip-container")).not.toHaveClass(/flipped/);
    await expect(page.locator(".canvas-stream")).toBeVisible();
  });
});

test.describe("Workflow CSS hooks", () => {
  async function hasSelector(page: Page, selector: string) {
    return page.evaluate((needle) => {
      for (const sheet of Array.from(document.styleSheets)) {
        try {
          for (const rule of Array.from(sheet.cssRules || [])) {
            if (rule instanceof CSSStyleRule && rule.selectorText.includes(needle)) {
              return true;
            }
          }
        } catch (_) {}
      }
      return false;
    }, selector);
  }

  test("wf-map-board CSS class is defined", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    expect(await hasSelector(page, "wf-map-board")).toBe(true);
  });

  test("wf-map-node CSS class is defined", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    expect(await hasSelector(page, "wf-map-node")).toBe(true);
  });

  test("wf-detail-tray CSS class is defined", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    expect(await hasSelector(page, "wf-detail-tray")).toBe(true);
  });

  test("wf-map-edge CSS class is defined", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    expect(await hasSelector(page, "wf-map-edge")).toBe(true);
  });
});

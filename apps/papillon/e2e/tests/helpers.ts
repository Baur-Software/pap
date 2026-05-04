import { Page, expect } from "@playwright/test";

/**
 * Wait for WASM app to mount. 30s covers slow CI runners.
 */
export async function waitForApp(page: Page): Promise<void> {
  await expect(page.locator(".app-shell-canvas")).toBeVisible({ timeout: 30_000 });
}

/**
 * Fill the topbar address input and press Enter.
 */
export async function submitPrompt(page: Page, text: string): Promise<void> {
  await page.locator(".topbar-address-input").fill(text);
  await page.locator(".topbar-address-input").press("Enter");
}

/**
 * Wait for any canvas block to appear in resolved state.
 */
export async function awaitBlock(page: Page, timeout = 15_000): Promise<void> {
  await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout });
}

/**
 * Wait for a block with a specific typed CSS class to appear.
 */
export async function awaitTypedBlock(
  page: Page,
  cssClass: string,
  timeout = 15_000
): Promise<void> {
  await expect(page.locator(cssClass).first()).toBeVisible({ timeout });
}

/**
 * Submit a prompt, wait for the first canvas block to appear, then pause
 * 400ms so WASM reactive handlers wire up before tests start clicking.
 */
export async function submitAndWaitForBlock(page: Page, prompt: string): Promise<void> {
  await submitPrompt(page, prompt);
  await expect(page.locator(".canvas-block").first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(400);
}

/**
 * Create a fresh empty canvas by navigating to "/" and clicking "+ New Canvas".
 * Closes the slide panel before returning.
 */
export async function createEmptyCanvas(page: Page): Promise<void> {
  await page.goto("/", { waitUntil: "commit" });
  await waitForApp(page);
  await page.locator(".topbar-brand").click();
  await page.getByText("+ New Canvas", { exact: true }).click();
  await expect(page.locator(".canvas-surface-status")).toContainText(
    "Approve workflow to render"
  );
  await expect(page.locator(".slide-panel.open")).toHaveCount(0);
}

/**
 * Navigate to Settings and open a named tab (e.g. "Templates", "Network",
 * "Orchestrator", "Identity"). Safe to call when already on the settings page.
 */
export async function goToSettingsTab(page: Page, tabName: string): Promise<void> {
  const settingsNav = page.locator(".settings-nav");
  const alreadyOnSettings = await settingsNav.isVisible().catch(() => false);
  if (!alreadyOnSettings) {
    await page.locator(".topbar-brand").click();
    await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
    await page.locator(".settings-overlay").waitFor({ state: "visible" });
    await expect(page.locator(".settings-nav")).toBeVisible({ timeout: 10_000 });
  }
  await page.locator(".settings-nav-link").filter({ hasText: tabName }).click();
  await expect(
    page.locator(".settings-nav-link.active").filter({ hasText: tabName })
  ).toBeVisible();
}

/**
 * Configure Ollama via IPC (bypasses UI fragility).
 * Sets Ollama as LLM provider with given endpoint and model.
 */
export async function configureOllamaViaIpc(
  page: Page,
  endpoint = "http://localhost:11434",
  model = "mistral:latest"
): Promise<void> {
  await page.evaluate(
    ([ep, m]) =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: ep, model: m } },
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: true,
        },
      }),
    [endpoint, model]
  );
}

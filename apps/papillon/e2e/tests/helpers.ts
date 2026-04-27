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

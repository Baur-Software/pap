import { Page, expect } from "@playwright/test";

/**
 * Wait for the WASM app to mount and render.
 *
 * The Leptos/WASM frontend compiles in the browser before rendering.
 * On CI runners this can take 30-60+ seconds for debug builds.
 * This helper waits for the app shell to appear in the DOM.
 */
export async function waitForApp(page: Page): Promise<void> {
  // The app renders <div class="app-shell-canvas"> as its root element.
  // Wait for this to appear, which confirms WASM loaded, compiled, and mounted.
  await expect(page.locator(".app-shell-canvas")).toBeVisible({ timeout: 60_000 });
}

import { Page, expect } from "@playwright/test";

/**
 * Wait for the WASM app to mount and render.
 *
 * V8 must compile the 2.2 MB release WASM on every new browser context.
 * On a 2-core CI runner this takes 90-120 seconds. The DOMContentLoaded
 * event won't fire until the <script type="module"> with `await init()`
 * finishes, so page.goto() alone can consume most of the test budget.
 *
 * This helper polls for the root .app-shell-canvas element with a
 * generous timeout that covers WASM compilation + app mounting.
 */
export async function waitForApp(page: Page): Promise<void> {
  await expect(page.locator(".app-shell-canvas")).toBeVisible({ timeout: 240_000 });
}

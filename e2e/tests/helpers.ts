import { Page, expect } from "@playwright/test";

/**
 * Wait for the WASM app to mount and render.
 *
 * V8 compiles and instantiates the 2.2 MB release WASM in ~15ms.
 * The actual bottleneck is module loading + Leptos CSR mount.
 * 30s timeout is generous for CI runners.
 */
export async function waitForApp(page: Page): Promise<void> {
  await expect(page.locator(".app-shell-canvas")).toBeVisible({ timeout: 30_000 });
}

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

test.describe("Papillion Smoke Tests", () => {
  test("WASM loads and app shell renders", async ({ page }) => {
    const messages: string[] = [];
    const pageErrors: string[] = [];

    page.on("console", (msg) => {
      messages.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on("pageerror", (err) => {
      pageErrors.push(`${err.name}: ${err.message}`);
    });

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Dump diagnostics for debugging
    console.log("[diag] console messages:", messages.length);
    for (const m of messages) console.log(`[diag]   ${m}`);
    if (pageErrors.length > 0) {
      console.log("[diag] page errors:");
      for (const e of pageErrors) console.log(`[diag]   ${e}`);
    }

    expect(pageErrors).toHaveLength(0);
  });

  test("frontend renders content (not blank screen)", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const bodyText = await page.locator("body").innerText();
    expect(bodyText.length).toBeGreaterThan(0);
  });

  test("no unhandled console errors on startup", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        errors.push(msg.text());
      }
    });
    page.on("pageerror", (err) => {
      errors.push(`${err.name}: ${err.message}`);
    });

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Filter out known benign warnings
    const real = errors.filter(
      (e) => !e.includes("integrity") && !e.includes("deprecated")
    );
    expect(real).toHaveLength(0);
  });

  test("Tauri mock is available", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const hasTauri = await page.evaluate(
      () => typeof (window as any).__TAURI__ !== "undefined"
    );
    expect(hasTauri).toBe(true);
  });

  test("status bar shows orchestrator state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const statusBar = page.locator(".status-bar");
    await expect(statusBar).toBeVisible();
  });
});

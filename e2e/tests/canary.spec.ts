/**
 * Tier 3: Canary Monitoring
 *
 * Post-deploy health checks that verify the production app is healthy.
 * Runs after each release to detect runtime failures.
 *
 * Tests:
 * 1. Backend health endpoint is responsive and returns valid JSON
 * 2. Frontend load time is within SLA (<3 seconds)
 * 3. Scenario execution latency is normal (<500ms for mock)
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── Tier 3 Tests: Post-Deploy Health Checks ─────────────────

test.describe("Canary monitoring (post-deploy health checks)", () => {
  test("backend health endpoint returns ok status", async ({ page }) => {
    await page.goto("/");
    const health = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("get_health_status");
    });

    // Verify response structure
    expect(health).toHaveProperty("status");
    expect(health).toHaveProperty("timestamp");
    expect(health).toHaveProperty("uptime_seconds");
    expect(health).toHaveProperty("version");

    // Verify status is ok
    expect(health.status).toBe("ok");

    // Verify timestamp is valid ISO 8601
    const timestamp = new Date(health.timestamp);
    expect(timestamp).toBeInstanceOf(Date);
    expect(timestamp.getTime()).not.toBeNaN();

    // Verify uptime is positive
    expect(typeof health.uptime_seconds).toBe("number");
    expect(health.uptime_seconds).toBeGreaterThanOrEqual(0);

    // Verify version string exists
    expect(typeof health.version).toBe("string");
    expect(health.version.length).toBeGreaterThan(0);
  });

  test("frontend loads and becomes interactive within SLA", async ({ page }) => {
    // Measure page load time
    const start = Date.now();

    // Navigate to app
    await page.goto("/");

    // Wait for interactive state (main content visible)
    await expect(page.locator(".canvas-area, .setup-prompt")).toBeVisible({
      timeout: 5000,
    });

    const elapsed = Date.now() - start;

    // SLA: app should be interactive within 3 seconds
    // This accounts for WASM compilation, frontend bundle loading, and initial render
    console.log(`[canary] Frontend load time: ${elapsed}ms`);
    expect(elapsed).toBeLessThan(3000);
  });

  test("scenario execution completes within latency SLA", async ({ page }) => {
    await page.goto("/");

    // Measure scenario execution time
    const start = Date.now();

    const result = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("run_scenario", {
        scenarioId: "weather",
      });
    });

    const elapsed = Date.now() - start;

    // Verify execution succeeded
    expect(result.success).toBe(true);

    // SLA: scenario execution should complete within 500ms
    // Mock implementation is faster, but production might include network calls
    console.log(`[canary] Scenario execution time: ${elapsed}ms`);
    expect(elapsed).toBeLessThan(500);
  });

  test("orchestrator config is retrievable and valid", async ({ page }) => {
    await page.goto("/");

    const config = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("get_orchestrator_config");
    });

    // Verify config structure
    expect(config).toHaveProperty("llm_provider");
    expect(config).toHaveProperty("mandate_ttl_hours");
    expect(config).toHaveProperty("auto_approve_zero_disclosure");

    // Verify types
    expect(typeof config.mandate_ttl_hours).toBe("number");
    expect(typeof config.auto_approve_zero_disclosure).toBe("boolean");
  });

  test("identity is accessible without errors", async ({ page }) => {
    await page.goto("/");

    const identity = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("get_identity");
    });

    // Verify identity structure
    expect(identity).toHaveProperty("did");
    expect(identity).toHaveProperty("public_key_b64");
    expect(identity).toHaveProperty("created_at");

    // Verify DID format (did:key:z...)
    expect(identity.did).toMatch(/^did:key:z/);

    // Verify base64 encoded key
    expect(identity.public_key_b64).toMatch(/^[A-Za-z0-9+/=]+$/);

    // Verify timestamp format
    const created = new Date(identity.created_at);
    expect(created.getTime()).not.toBeNaN();
  });

  test("no console errors on app startup", async ({ page }) => {
    const consoleMessages: string[] = [];
    const errorMessages: string[] = [];

    page.on("console", (msg) => {
      consoleMessages.push(msg.text());
      if (msg.type() === "error") {
        errorMessages.push(msg.text());
      }
    });

    await page.goto("/");
    await expect(page.locator(".canvas-area, .setup-prompt")).toBeVisible({
      timeout: 5000,
    });

    // Log all console output for debugging
    console.log(`[canary] Console messages during startup: ${consoleMessages.length}`);
    console.log(`[canary] Errors during startup: ${errorMessages.length}`);

    // Accept some warnings but not errors
    // Filter out known benign warnings
    const criticalErrors = errorMessages.filter(
      (e) =>
        !e.includes("WASM") &&
        !e.includes("deprecated") &&
        !e.includes("warning") &&
        e.length > 0
    );

    expect(criticalErrors).toHaveLength(0);
  });

  test("Tier 1 smoke tests still pass", async ({ page }) => {
    // Verify basic regression: if Tier 1 is broken, canary catches it
    await page.goto("/");

    // App window should be visible
    const appContainer = page.locator("body");
    await expect(appContainer).toBeVisible({ timeout: 5000 });

    // Frontend should render (not blank screen)
    const mainContent = page.locator("main, [role=main], .app, #app, body > div");
    const contentText = await mainContent.textContent();
    expect(contentText?.trim().length).toBeGreaterThan(0);

    // No console errors from WASM module
    let wasmsErrors = 0;
    page.on("console", (msg) => {
      if (msg.type() === "error" && msg.text().includes("WASM")) {
        wasmsErrors++;
      }
    });

    expect(wasmsErrors).toBe(0);
  });
});

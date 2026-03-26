/**
 * Standalone Web Build Smoke Tests (Tier 1)
 *
 * These tests verify the Papillion frontend works correctly when served
 * as a standalone web build — NO Tauri mock injected, no desktop shell.
 * The app should degrade gracefully: shell renders, pages are navigable,
 * and no JS errors from missing Tauri IPC.
 *
 * Runs against `http-server dist/` (same as CI web-build workflow).
 */

import { test, expect } from "@playwright/test";
import { waitForApp } from "./helpers";

// Deliberately NO installTauriMock — this tests the real web-only path.

// ── App Shell ────────────────────────────────────────────────

test.describe("Web standalone: app shell", () => {
  test("WASM loads and app shell renders without Tauri", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".app-shell-canvas")).toBeVisible();
  });

  test("top bar renders with identity placeholder", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".topbar")).toBeVisible();
    // Without Tauri, no identity is loaded — topbar shows "No identity"
    await expect(page.locator(".topbar-identity")).toContainText("No identity");
  });

  test("status bar shows disconnected state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const statusBar = page.locator(".status-bar");
    await expect(statusBar).toBeVisible();
    // Default OrchestratorStatus is Disconnected → status bar text is "Disconnected"
    await expect(statusBar).toContainText("Disconnected");
  });

  test("top bar shows offline orchestrator status", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Topbar maps Disconnected → "Offline"
    await expect(page.locator(".topbar-status")).toContainText("Offline");
  });

  test("navigation menu opens and shows links", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-menu-btn").click();
    await expect(page.locator(".menu-dropdown")).toBeVisible();
    await expect(page.locator("text=Browse Registries")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Settings")).toBeVisible();
  });
});

// ── Canvas Page ──────────────────────────────────────────────

test.describe("Web standalone: canvas page", () => {
  test("shows empty state with inspiration lines", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".canvas-area")).toBeVisible();
    await expect(page.locator(".canvas-empty")).toBeVisible();
    await expect(page.locator(".inspiration-line").first()).toBeVisible();
  });

  test("shows setup prompt instead of inline prompt", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Orchestrator is Disconnected → SetupPrompt renders, not InlinePrompt
    await expect(page.locator(".canvas-prompt-setup")).toBeVisible();
    await expect(
      page.locator("text=Configure an LLM provider")
    ).toBeVisible();
    await expect(page.locator("text=Open Settings")).toBeVisible();
  });
});

// ── Settings Page ────────────────────────────────────────────

test.describe("Web standalone: settings page", () => {
  test("renders all five tabs", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".settings-tab")).toHaveCount(5);
    await expect(page.locator(".settings-tab").nth(0)).toHaveText("General");
    await expect(page.locator(".settings-tab").nth(1)).toHaveText("Profiles");
    await expect(page.locator(".settings-tab").nth(2)).toHaveText("Templates");
    await expect(page.locator(".settings-tab").nth(3)).toHaveText("Identity");
    await expect(page.locator(".settings-tab").nth(4)).toHaveText("Advanced");
  });

  test("tabs are clickable and switch content", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);

    // Start on General — should show LLM Provider heading
    await expect(page.locator("text=LLM Provider")).toBeVisible();

    // Switch to Identity tab — General content should disappear
    await page.locator(".settings-tab").nth(3).click();
    await expect(page.locator("text=LLM Provider")).not.toBeVisible();

    // Switch to Advanced tab — shows Registry Browser
    await page.locator(".settings-tab").nth(4).click();
    await expect(page.locator("text=Registry Browser")).toBeVisible();
  });
});

// ── Browse Page ──────────────────────────────────────────────

test.describe("Web standalone: browse page", () => {
  test("shows registry browser heading", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator("text=Browse Registries")).toBeVisible();
  });

  test("shows disconnected empty state", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);

    // Registry is not connected → shows prompt to enter URL
    await expect(
      page.locator("text=Enter a registry URL in the address bar")
    ).toBeVisible();
  });
});

// ── Graceful Degradation ─────────────────────────────────────

test.describe("Web standalone: graceful degradation", () => {
  test("no JS errors from missing Tauri IPC", async ({ page }) => {
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

    // Filter known benign messages
    const real = errors.filter(
      (e) =>
        !e.includes("integrity") &&
        !e.includes("deprecated") &&
        !e.includes("wasm") &&
        !e.includes("source map") &&
        !e.includes("favicon")
    );

    expect(real).toHaveLength(0);
  });

  test("Tauri IPC is NOT available", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const hasTauri = await page.evaluate(
      () => typeof (window as any).__TAURI__ !== "undefined"
    );
    expect(hasTauri).toBe(false);
  });

  test("navigating between pages produces no errors", async ({ page }) => {
    const errors: string[] = [];

    page.on("pageerror", (err) => {
      errors.push(`${err.name}: ${err.message}`);
    });

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Navigate to settings
    await page.goto("/settings", { waitUntil: "commit" });
    await expect(page.locator(".settings-tab").first()).toBeVisible();

    // Navigate to browse
    await page.goto("/browse", { waitUntil: "commit" });
    await expect(page.locator("text=Browse Registries")).toBeVisible();

    // Navigate to activity
    await page.goto("/activity", { waitUntil: "commit" });
    await expect(page.locator(".app-shell-canvas")).toBeVisible();

    // Back to home
    await page.goto("/", { waitUntil: "commit" });
    await expect(page.locator(".canvas-area")).toBeVisible();

    expect(errors).toHaveLength(0);
  });
});

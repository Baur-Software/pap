/**
 * Standalone Web Build Smoke Tests (Tier 1)
 *
 * These tests verify the Papillon frontend works correctly when served
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

  test("top bar renders with brand icon", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".topbar")).toBeVisible();
    // The identity DID is no longer displayed in the topbar — confirm brand icon is present
    await expect(page.locator(".topbar-brand-icon")).toBeVisible();
  });

  test("status bar shows agents-only state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const statusBar = page.locator(".status-bar");
    await expect(statusBar).toBeVisible();
    // Browser mode sets Unconfigured → status bar shows "Agents only"
    await expect(statusBar).toContainText("Agents only");
  });

  test("top bar shows workflow toggle button", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Status dot replaced by the canvas flip-toggle button in the topbar right zone
    await expect(page.locator(".canvas-flip-toggle")).toBeVisible();
    await expect(page.locator(".canvas-flip-toggle")).toContainText("Workflow");
  });

  test("navigation panel opens and shows links", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Browse Agents" })).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" })).toBeVisible();
  });
});

// ── Canvas Page ──────────────────────────────────────────────

test.describe("Web standalone: canvas page", () => {
  test("shows single-column canvas with empty state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".canvas-page")).toBeVisible();
    // No Tauri backend → no seed → shows the empty state (prompt only)
    await expect(page.locator(".canvas-empty-state")).toBeVisible();
  });

  test("shows address bar prompt for user queries", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // The prompt input is now .topbar-address-input in the topbar, not a canvas-inline element
    await expect(page.locator(".topbar-address-input")).toBeVisible();
  });
});

// ── Settings Page ────────────────────────────────────────────
// Navigate via sidebar settings link — http-server has no SPA fallback.

test.describe("Web standalone: settings page", () => {
  test("renders settings left nav with all sections", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Navigate to settings via slide panel
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" }).click();

    await expect(page.locator(".settings-nav")).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Profiles" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Identity" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Templates" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Privacy" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Advanced" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Appearance" })).toBeVisible();
  });

  test("nav links are clickable and switch content", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // Navigate to settings via the slide panel (direct link click is inside the panel)
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" }).click();

    // Default tab is Profiles — settings nav should be visible
    await expect(page.locator(".settings-nav")).toBeVisible();

    // Switch to Orchestrator tab — should show AI Model heading
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();
    await expect(page.locator("text=AI Model")).toBeVisible();

    // Switch to Identity tab — Orchestrator content should disappear
    await page.locator(".settings-nav-link").filter({ hasText: "Identity" }).click();
    await expect(page.locator("text=AI Model")).not.toBeVisible();

    // Switch to Advanced tab — shows Saved Registries
    await page.locator(".settings-nav-link").filter({ hasText: "Advanced" }).click();
    await expect(page.locator("text=Saved Registries")).toBeVisible();
  });
});

// ── Browse Page ──────────────────────────────────────────────
// Navigate via the slide panel (brand button → Browse Agents link).

test.describe("Web standalone: browse page", () => {
  test("shows registry browser heading", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Browse Agents" }).click();

    await expect(page.locator("h2:has-text('Browse Registries')")).toBeVisible();
  });

  test("shows disconnected empty state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Browse Agents" }).click();

    // Registry is not connected → shows quickstart to connect
    await expect(
      page.locator("text=Connect to a Chrysalis Registry")
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

    // Navigate to settings via slide panel
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" }).click();
    await expect(page.locator(".settings-nav")).toBeVisible();

    // Navigate to browse via slide panel
    await page.locator(".topbar-brand").click();
    await page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Browse Agents" }).click();
    await expect(page.locator("h2:has-text('Browse Registries')")).toBeVisible();

    // Back to home canvas page via direct navigation
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".canvas-page")).toBeVisible();

    expect(errors).toHaveLength(0);
  });
});

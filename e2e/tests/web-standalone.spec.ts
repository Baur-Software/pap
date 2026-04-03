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

  test("top bar renders with identity", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".topbar")).toBeVisible();
    // WebService auto-creates a default identity in browser mode
    const identityText = await page.locator(".topbar-identity").innerText();
    expect(identityText.length).toBeGreaterThan(0);
  });

  test("status bar shows agents-only state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const statusBar = page.locator(".status-bar");
    await expect(statusBar).toBeVisible();
    // Browser mode sets Unconfigured → status bar shows "Agents only"
    await expect(statusBar).toContainText("Agents only");
  });

  test("top bar shows agents-only orchestrator status", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Browser mode: Unconfigured → topbar shows "Agents only"
    await expect(page.locator(".topbar-status")).toContainText("Agents only");
  });

  test("navigation menu opens and shows links", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-menu-btn").click();
    await expect(page.locator(".menu-dropdown")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Browse Registries")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Settings")).toBeVisible();
  });
});

// ── Canvas Page ──────────────────────────────────────────────

test.describe("Web standalone: canvas page", () => {
  test("shows new-tab empty state with agent tiles", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".canvas-area")).toBeVisible();
    // No Tauri backend → no seed → shows the new-tab page with agent tiles
    await expect(page.locator(".canvas-empty")).toBeVisible();
  });

  test("shows inline prompt for user queries", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // InlinePrompt renders inside the new-tab canvas
    await expect(page.locator(".palette-input")).toBeVisible();
  });
});

// ── Settings Page ────────────────────────────────────────────
// Navigate via topbar gear icon — http-server has no SPA fallback.

test.describe("Web standalone: settings page", () => {
  test("renders all settings tabs", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-settings-btn").click();

    await expect(page.locator(".settings-tab")).toHaveCount(6);
    await expect(page.locator(".settings-tab").nth(0)).toHaveText("General");
    await expect(page.locator(".settings-tab").nth(1)).toHaveText("Profiles");
    await expect(page.locator(".settings-tab").nth(2)).toHaveText("Templates");
    await expect(page.locator(".settings-tab").nth(3)).toHaveText("Identity");
    await expect(page.locator(".settings-tab").nth(4)).toHaveText("Advanced");
    await expect(page.locator(".settings-tab").nth(5)).toHaveText("MANDATES");
  });

  test("tabs are clickable and switch content", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-settings-btn").click();

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
// Navigate via hamburger menu — http-server has no SPA fallback.

test.describe("Web standalone: browse page", () => {
  test("shows registry browser heading", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-menu-btn").click();
    await page.locator(".menu-dropdown >> text=Browse Registries").click();

    await expect(page.locator("h2:has-text('Browse Registries')")).toBeVisible();
  });

  test("shows disconnected empty state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-menu-btn").click();
    await page.locator(".menu-dropdown >> text=Browse Registries").click();

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

    // Navigate to settings via gear icon
    await page.locator(".topbar-settings-btn").click();
    await expect(page.locator(".settings-tab").first()).toBeVisible();

    // Navigate to browse via menu
    await page.locator(".topbar-menu-btn").click();
    await page.locator(".menu-dropdown >> text=Browse Registries").click();
    await expect(page.locator("h2:has-text('Browse Registries')")).toBeVisible();

    // Back to home via menu
    await page.locator(".topbar-menu-btn").click();
    await page.locator(".menu-dropdown >> text=New Canvas").click();
    await expect(page.locator(".canvas-area")).toBeVisible();

    expect(errors).toHaveLength(0);
  });
});

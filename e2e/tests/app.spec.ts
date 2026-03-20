import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── Top Bar & App Shell ──────────────────────────────────────

test.describe("App shell", () => {
  test("renders top bar with identity and status", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".topbar")).toBeVisible();
    await expect(page.locator(".topbar-identity")).not.toBeEmpty();
    await expect(page.locator(".topbar-status")).toBeVisible();
  });

  test("shows orchestrator status in top bar", async ({ page }) => {
    await page.goto("/");
    // Mock returns "Disconnected" → topbar maps to "Offline"
    await expect(page.locator(".topbar-status")).toContainText("Offline");
  });

  test("shows settings gear link", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".topbar-settings-btn")).toBeVisible();
  });

  test("hamburger menu opens and shows nav items", async ({ page }) => {
    // Navigate to a non-canvas page to avoid the auto-opened command palette
    await page.goto("/activity");
    await page.locator(".topbar-menu-btn").click();
    await expect(page.locator(".menu-dropdown")).toBeVisible();
    await expect(page.locator("text=Browse Registries")).toBeVisible();
    await expect(page.locator(".menu-dropdown >> text=Settings")).toBeVisible();
  });

  test("shows status bar footer", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".status-bar")).toBeVisible();
  });
});

// ── Canvas Page (Home) ───────────────────────────────────────

test.describe("Canvas page", () => {
  test("shows empty state with inspiration lines", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".canvas-area")).toBeVisible();
    await expect(page.locator(".canvas-empty")).toBeVisible();
    await expect(page.locator(".inspiration-line").first()).toBeVisible();
  });

  test("shows keyboard shortcut hint", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".canvas-shortcut-hint")).toBeVisible();
    await expect(page.locator("kbd")).toContainText("\u{2318}K");
  });

  test("command palette auto-opens on first visit", async ({ page }) => {
    await page.goto("/");
    // Palette auto-opens when no canvases exist
    await expect(page.locator(".palette")).toBeVisible({ timeout: 5000 });
    await expect(
      page.locator(".palette-label")
    ).toContainText("What do you want to build?");
  });

  test("command palette shows suggestion buttons", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".palette")).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".palette-suggestion").first()).toBeVisible();
  });

  test("command palette input accepts text", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".palette")).toBeVisible({ timeout: 5000 });
    await page.locator(".palette-input").fill("Search for flights");
    await expect(page.locator(".palette-input")).toHaveValue("Search for flights");
    // Suggestions should hide when input has text
    await expect(page.locator(".palette-suggestion").first()).not.toBeVisible();
  });
});

// ── Activity Page ────────────────────────────────────────────

test.describe("Activity page", () => {
  test("shows empty state when no runs", async ({ page }) => {
    await page.goto("/activity");
    await expect(
      page.locator("text=No recent activity")
    ).toBeVisible();
  });
});

// ── Settings Page ────────────────────────────────────────────

test.describe("Settings page", () => {
  test("renders three tabs", async ({ page }) => {
    await page.goto("/settings");
    await expect(page.locator(".settings-tab")).toHaveCount(3);
    await expect(page.locator(".settings-tab").first()).toHaveText("General");
    await expect(page.locator(".settings-tab").nth(1)).toHaveText("Identity");
    await expect(page.locator(".settings-tab").nth(2)).toHaveText("Advanced");
  });

  test("General tab shows LLM Provider config", async ({ page }) => {
    await page.goto("/settings");
    await expect(page.locator("text=LLM Provider")).toBeVisible();
    // Provider select is the first select on the page
    await expect(page.locator("select").first()).toBeVisible();
  });

  test("Identity tab shows identity info and backup warning", async ({
    page,
  }) => {
    await page.goto("/settings");
    await page.locator(".settings-tab").nth(1).click();

    // Should show backup warning (key not backed up)
    await expect(page.locator(".backup-warning")).toBeVisible();
    await expect(
      page.locator("text=Your key has not been backed up!")
    ).toBeVisible();

    // Should show identity DID
    await expect(page.getByText("DID:", { exact: true })).toBeVisible();

    // Export and Import buttons
    await expect(page.locator("text=Export Key")).toBeVisible();
    await expect(page.locator("text=Import Key")).toBeVisible();
  });

  test("Export key shows seed and clears backup warning", async ({ page }) => {
    await page.goto("/settings");
    await page.locator(".settings-tab").nth(1).click();
    await expect(page.locator(".backup-warning")).toBeVisible();

    // Click export
    await page.locator("text=Export Key").click();

    // Should show exported key
    await expect(page.locator(".key-display")).toBeVisible();
    await expect(page.locator(".key-display")).toContainText(
      "dGVzdC1zZWVkLWtleS1iYXNlNjQ"
    );

    // Backup warning should disappear
    await expect(page.locator(".backup-warning")).not.toBeVisible();
  });

  test("Add Successor form works", async ({ page }) => {
    await page.goto("/settings");
    await page.locator(".settings-tab").nth(1).click();

    // Wait for Identity tab content
    await expect(page.locator("text=Designated Successors")).toBeVisible();

    // Click Add Successor
    await page.getByRole("button", { name: "Add Successor" }).click();

    // Wait for form to appear
    await expect(page.locator('input[placeholder="did:key:z..."]')).toBeVisible();

    // Fill in successor form
    await page.locator('input[placeholder="did:key:z..."]').fill(
      "did:key:z6MkSuccessor123"
    );
    await page.locator('input[placeholder="Optional notes..."]').fill(
      "My estate executor"
    );

    // Save — the form's Save button (inside the successor form area)
    await page
      .locator(".setup-inputs")
      .last()
      .getByRole("button", { name: "Save" })
      .click();

    // Should show successor entry (wait for async response)
    await expect(
      page.locator(".successor-entry")
    ).toBeVisible({ timeout: 10_000 });
  });

  test("switching tabs works", async ({ page }) => {
    await page.goto("/settings");

    // Start on General
    await expect(page.locator("text=LLM Provider")).toBeVisible();

    // Switch to Identity
    await page.locator(".settings-tab").nth(1).click();
    await expect(page.locator("text=Export Key")).toBeVisible();

    // Switch to Advanced
    await page.locator(".settings-tab").nth(2).click();
    await expect(page.locator("text=Registry Browser")).toBeVisible();
  });
});

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── Navigation & Layout ───────────────────────────────────────

test.describe("App shell", () => {
  test("renders sidebar with identity and nav links", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".sidebar")).toBeVisible();
    await expect(page.locator(".identity-badge .label")).toHaveText("Principal");
    await expect(page.locator(".identity-badge .did")).not.toBeEmpty();

    // Nav items
    await expect(page.locator('a.nav-item:has-text("Home")')).toBeVisible();
    await expect(page.locator('a.nav-item:has-text("Activity")')).toBeVisible();
    await expect(page.locator('a.nav-item:has-text("Settings")')).toBeVisible();
  });

  test("shows orchestrator status badge", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".status-badge")).toContainText("Demo Mode");
  });

  test("header shows Papillion title", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".header h1")).toContainText("Papillion");
  });
});

// ── Home Page ─────────────────────────────────────────────────

test.describe("Home page", () => {
  test("displays scenario cards", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".scenario-card")).toHaveCount(3);
  });

  test("shows scenario titles", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".scenario-title").first()).toHaveText(
      "Check the Weather"
    );
    await expect(page.locator(".scenario-title").nth(1)).toHaveText(
      "Book a Flight"
    );
    await expect(page.locator(".scenario-title").nth(2)).toHaveText(
      "Send Payment"
    );
  });

  test("shows zero disclosure badge for weather scenario", async ({
    page,
  }) => {
    await page.goto("/");
    await expect(
      page.locator(".scenario-card").first().locator(".scenario-disclosure.zero")
    ).toHaveText("Zero Disclosure");
  });

  test("shows fields-required badge for booking scenario", async ({
    page,
  }) => {
    await page.goto("/");
    await expect(
      page
        .locator(".scenario-card")
        .nth(1)
        .locator(".scenario-disclosure.required")
    ).toContainText("3 fields required");
  });

  test("clicking a scenario navigates to scenario page", async ({ page }) => {
    await page.goto("/");
    await page.locator(".scenario-card").first().click();
    await expect(page).toHaveURL(/\/scenario\/weather/);
  });
});

// ── Scenario Page ─────────────────────────────────────────────

test.describe("Scenario page", () => {
  test("shows scenario details and handshake stepper", async ({ page }) => {
    await page.goto("/");
    await page.locator(".scenario-card").first().click();
    await expect(page).toHaveURL(/\/scenario\/weather/);

    // Title + agent name
    await expect(page.locator("h2")).toContainText("Check the Weather");
    await expect(page.locator("text=WeatherBot")).toBeVisible();

    // 6 handshake steps
    await expect(page.locator(".handshake-step")).toHaveCount(6);

    // Run Demo button
    await expect(page.locator(".btn-run")).toBeVisible();
    await expect(page.locator(".btn-run")).toHaveText("Run Demo");
  });

  test("shows zero disclosure message for weather", async ({ page }) => {
    await page.goto("/");
    await page.locator(".scenario-card").first().click();
    await expect(
      page.locator("text=None \u2014 zero disclosure interaction")
    ).toBeVisible();
  });

  test("Run Demo executes handshake and shows receipt", async ({ page }) => {
    await page.goto("/");
    await page.locator(".scenario-card").first().click();
    await expect(page.locator(".btn-run")).toBeVisible();

    // Click Run Demo
    await page.locator(".btn-run").click();

    // Button should show Running... or Completed
    await expect(page.locator(".btn-run")).not.toHaveText("Run Demo");

    // Wait for all steps to animate (6 steps * 300ms + buffer)
    await page.waitForTimeout(3000);

    // Button should show Completed
    await expect(page.locator(".btn-run")).toHaveText("Completed");

    // Receipt card should appear
    await expect(page.locator("text=Transaction Receipt")).toBeVisible();
    await expect(page.locator("code").filter({ hasText: "session-abc123" })).toBeVisible();
    await expect(page.locator("code").filter({ hasText: "weather.lookup" }).first()).toBeVisible();
  });

  test("back button returns to home", async ({ page }) => {
    await page.goto("/");
    await page.locator(".scenario-card").first().click();
    await expect(page).toHaveURL(/\/scenario/);

    await page.locator("text=\u2190 Back").click();
    await expect(page).toHaveURL(/\/$/);
  });
});

// ── Activity Page ─────────────────────────────────────────────

test.describe("Activity page", () => {
  test("shows empty state when no runs", async ({ page }) => {
    await page.goto("/activity");
    await expect(
      page.locator("text=No recent activity")
    ).toBeVisible();
  });

  test("shows completed run after running a scenario", async ({ page }) => {
    // Run a scenario first
    await page.goto("/");
    await page.locator(".scenario-card").first().click();
    await page.locator(".btn-run").click();
    await page.waitForTimeout(3000);

    // Navigate to activity
    await page.locator('a.nav-item:has-text("Activity")').click();
    await expect(page).toHaveURL(/\/activity/);

    // Should show the completed run
    await expect(page.locator("text=WeatherBot")).toBeVisible();
    await expect(page.locator("text=Completed")).toBeVisible();
  });
});

// ── Settings Page ─────────────────────────────────────────────

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
    await expect(page.locator("select")).toBeVisible();
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

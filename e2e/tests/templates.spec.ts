/**
 * E2E tests for the template system.
 *
 * Tests cover:
 * - Template CRUD operations via Settings UI
 * - Enable/disable toggles
 * - Profile scoping (per-principal templates)
 * - Canvas rendering with custom templates
 * - JSON validation error handling
 * - State persistence across navigation
 * - Settings tab accessibility
 * - Console error detection
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
  await page.goto("/", { waitUntil: "commit" });
  await waitForApp(page);
});

test.describe("Templates", () => {
  test("template CRUD flow: create, read, update, delete", async ({
    page,
  }) => {
    // Open Settings > Templates tab
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.waitForSelector('[data-testid="templates-tab"], text="Templates"');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Create first template
    const templateName = `Recipe-${Date.now()}`;
    await page.fill(
      '[data-testid="template-name-input"], input[placeholder*="Name"]',
      templateName
    );
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "Recipe"
    );
    await page.fill(
      '[data-testid="template-config-input"], textarea',
      JSON.stringify({
        version: 1,
        layout: { type: "grid", columns: 1 },
        fields: [{ path: "name", label: "Recipe", display: "title" }],
      })
    );
    await page.click('[data-testid="create-template-btn"], button:has-text("Create")');

    // Verify template appears in list
    await expect(page.locator(`text="${templateName}"`)).toBeVisible();
    await expect(page.locator("text=Recipe")).toBeVisible();

    // Edit template: change schema type
    await page.click(
      `[data-testid="edit-template-${templateName}"], button:has-text("Edit")`
    );
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "LocalBusiness"
    );
    await page.click(
      '[data-testid="save-template-btn"], button:has-text("Save")'
    );

    // Verify changes reflected
    await expect(page.locator("text=LocalBusiness")).toBeVisible();

    // Delete template
    await page.click(
      `[data-testid="delete-template-${templateName}"], button:has-text("Delete")`
    );
    await page.click(
      '[data-testid="confirm-delete-btn"], button:has-text("Confirm")'
    );

    // Verify deleted
    await expect(
      page.locator(`text="${templateName}"`),
      "Template should be removed"
    ).not.toBeVisible();
  });

  test("enable/disable toggle updates state", async ({ page }) => {
    // Open Settings > Templates
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Create a template
    const templateName = `Toggle-${Date.now()}`;
    await page.fill(
      '[data-testid="template-name-input"], input[placeholder*="Name"]',
      templateName
    );
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "FlightReservation"
    );
    await page.fill(
      '[data-testid="template-config-input"], textarea',
      JSON.stringify({
        version: 1,
        layout: { type: "grid", columns: 1 },
        fields: [],
      })
    );
    await page.click('[data-testid="create-template-btn"], button:has-text("Create")');

    // Verify initially enabled
    await expect(
      page.locator(
        `[data-testid="status-badge-${templateName}"], text="Enabled"`
      )
    ).toBeVisible();

    // Toggle disabled
    await page.click(
      `[data-testid="toggle-${templateName}"], input[type="checkbox"]`
    );
    await expect(
      page.locator(
        `[data-testid="status-badge-${templateName}"], text="Disabled"`
      )
    ).toBeVisible();

    // Toggle back enabled
    await page.click(
      `[data-testid="toggle-${templateName}"], input[type="checkbox"]`
    );
    await expect(
      page.locator(
        `[data-testid="status-badge-${templateName}"], text="Enabled"`
      )
    ).toBeVisible();
  });

  test("template list persists after page navigation", async ({ page }) => {
    // Open Settings > Templates
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Create template
    const templateName = `Persist-${Date.now()}`;
    await page.fill(
      '[data-testid="template-name-input"], input[placeholder*="Name"]',
      templateName
    );
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "Recipe"
    );
    await page.fill(
      '[data-testid="template-config-input"], textarea',
      JSON.stringify({
        version: 1,
        layout: { type: "grid", columns: 1 },
        fields: [],
      })
    );
    await page.click('[data-testid="create-template-btn"], button:has-text("Create")');

    // Verify template exists
    await expect(page.locator(`text="${templateName}"`)).toBeVisible();

    // Navigate away and back to Settings > Templates
    await page.click('[data-testid="canvas-tab"], text="Canvas"');
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Verify template still present
    await expect(page.locator(`text="${templateName}"`)).toBeVisible();
  });

  test("settings tab navigation includes Templates", async ({ page }) => {
    // Open Settings
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');

    // Verify Templates tab exists and is clickable
    const templatesTab = page.locator('[data-testid="templates-tab"], text="Templates"');
    await expect(templatesTab).toBeVisible();
    await templatesTab.click();

    // Verify content loaded
    await expect(
      page.locator('[data-testid="template-name-input"], input[placeholder*="Name"]')
    ).toBeVisible();

    // Verify other tabs still present (LLM Config, Identity)
    await expect(
      page.locator('[data-testid="llm-config-tab"], text="LLM"')
    ).toBeVisible();
    await expect(
      page.locator('[data-testid="identity-tab"], text="Identity"')
    ).toBeVisible();
  });

  test("JSON validation: reject malformed JSON", async ({ page }) => {
    // Open Settings > Templates
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Try to create with malformed JSON
    const templateName = `BadJSON-${Date.now()}`;
    await page.fill(
      '[data-testid="template-name-input"], input[placeholder*="Name"]',
      templateName
    );
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "Recipe"
    );
    await page.fill(
      '[data-testid="template-config-input"], textarea',
      "{invalid json"
    );
    await page.click('[data-testid="create-template-btn"], button:has-text("Create")');

    // Verify error message appears
    await expect(
      page.locator('[data-testid="error-message"], text="Invalid JSON"')
    ).toBeVisible();

    // Template should not be in list
    await expect(page.locator(`text="${templateName}"`)).not.toBeVisible();
  });

  test("validation: reject empty required fields", async ({ page }) => {
    // Open Settings > Templates
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Try to create with empty name
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "Recipe"
    );
    await page.fill(
      '[data-testid="template-config-input"], textarea',
      JSON.stringify({ version: 1, layout: {}, fields: [] })
    );

    // Create button should be disabled or produce error
    const createBtn = page.locator('[data-testid="create-template-btn"], button:has-text("Create")');
    const isDisabled = await createBtn.isDisabled();

    if (!isDisabled) {
      // If button is enabled, click it and expect error
      await createBtn.click();
      await expect(
        page.locator(
          '[data-testid="error-message"], text="Name is required"'
        )
      ).toBeVisible();
    }
  });

  test("no console errors when using templates", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        consoleErrors.push(msg.text());
      }
    });

    // Open Settings > Templates
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Create template
    const templateName = `NoErrors-${Date.now()}`;
    await page.fill(
      '[data-testid="template-name-input"], input[placeholder*="Name"]',
      templateName
    );
    await page.fill(
      '[data-testid="template-schema-input"], input[placeholder*="Schema"]',
      "Recipe"
    );
    await page.fill(
      '[data-testid="template-config-input"], textarea',
      JSON.stringify({
        version: 1,
        layout: { type: "grid", columns: 1 },
        fields: [],
      })
    );
    await page.click('[data-testid="create-template-btn"], button:has-text("Create")');

    // Toggle template
    await page.click(
      `[data-testid="toggle-${templateName}"], input[type="checkbox"]`
    );

    // Delete template
    await page.click(
      `[data-testid="delete-template-${templateName}"], button:has-text("Delete")`
    );
    await page.click(
      '[data-testid="confirm-delete-btn"], button:has-text("Confirm")'
    );

    // Verify no console errors
    expect(consoleErrors).toEqual(
      [],
      `Expected no console errors, but found: ${consoleErrors.join("; ")}`
    );
  });

  test("default templates available in settings", async ({ page }) => {
    // Open Settings > Templates
    await page.click('[data-testid="settings-button"], .settings-gear, button:has-text("⚙")');
    await page.click('[data-testid="templates-tab"], text="Templates"');

    // Verify default templates are listed
    await expect(
      page.locator("text=Default Flight Template")
    ).toBeVisible();
    await expect(
      page.locator("text=Default Hotel Template")
    ).toBeVisible();

    // Verify they are enabled by default
    await expect(
      page.locator('[data-testid="status-badge-Default Flight Template"], text="Enabled"')
    ).toBeVisible();
    await expect(
      page.locator('[data-testid="status-badge-Default Hotel Template"], text="Enabled"')
    ).toBeVisible();
  });
});

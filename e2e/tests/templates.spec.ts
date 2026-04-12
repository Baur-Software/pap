/**
 * E2E tests for the template system.
 *
 * Tests cover:
 * - Template CRUD operations via Settings UI
 * - Enable/disable toggles
 * - Canvas rendering with custom templates
 * - JSON validation error handling
 * - State persistence across navigation
 * - Settings tab accessibility
 * - Console error detection
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

/** A valid template config JSON string (validation requires at least one field). */
const VALID_CONFIG = JSON.stringify({
  version: 1,
  layout: { type: "grid", columns: 1 },
  fields: [{ path: "name", label: "Name", display: "title" }],
});

/** Navigate to Settings > Templates tab and wait for content.
 *
 * Uses in-app SPA navigation (sidebar settings link click) so the Leptos router
 * handles the transition without a full page reload — this preserves in-memory mock
 * state (e.g. created templates) across navigation in the same test.
 */
async function goToTemplatesTab(page: import("@playwright/test").Page) {
  await page.locator('a[href="/settings"]').click();
  await expect(page.locator(".settings-tab", { hasText: "TEMPLATES" })).toBeVisible();
  await page.locator(".settings-tab", { hasText: "TEMPLATES" }).click();
  // Wait for the create form to appear (confirms tab content loaded)
  await expect(page.locator('input[placeholder*="Name"]')).toBeVisible();
}

/** Create a template through the UI form. */
async function createTemplate(
  page: import("@playwright/test").Page,
  name: string,
  schemaType: string,
  config: string = VALID_CONFIG,
) {
  await page.locator('input[placeholder*="Name"]').fill(name);
  await page.locator('input[placeholder*="Schema"]').fill(schemaType);
  await page.locator("textarea").first().fill(config);
  await page.locator('button:has-text("Create Template")').click();
  // Wait for success message
  await expect(page.getByText("Template created successfully")).toBeVisible({ timeout: 10000 });
}

/**
 * Get the template row locator. Template rows have a checkbox + name + buttons.
 * We find the specific row by filtering for one that contains the template name text.
 */
function templateRow(page: import("@playwright/test").Page, name: string) {
  // Each template row is a flex div with bg-tertiary containing the template name
  return page
    .locator('div[style*="background: var(--bg-tertiary)"]')
    .filter({ hasText: name });
}

test.describe("Templates", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
  });
  test("template CRUD flow: create, read, update, delete", async ({
    page,
  }) => {
    await goToTemplatesTab(page);

    // Create first template
    const templateName = `Recipe-${Date.now()}`;
    await createTemplate(page, templateName, "Recipe");

    // Verify template appears in list
    const row = templateRow(page, templateName);
    await expect(row).toBeVisible();

    // Edit template: click Edit button in the row
    await row.locator('button:has-text("Edit")').click();

    // Wait for the edit modal to appear (it has "Edit Template" heading)
    await expect(page.getByText("Edit Template")).toBeVisible();

    // Fill schema in the edit modal — the modal is a fixed overlay;
    // find the second schema-type input on the page (edit modal's input)
    // The edit modal's inputs don't have placeholders, but they have labels.
    // Use the modal container to scope the selector.
    const modal = page.locator('div[style*="position: fixed"]').filter({ hasText: "Edit Template" });
    const editSchemaInput = modal.locator('input[type="text"]').nth(1); // 0=name, 1=schema
    await editSchemaInput.fill("LocalBusiness");
    await modal.locator('button:has-text("Save")').click();

    // Wait for modal to close and verify changes reflected in the list
    await expect(page.getByText("Edit Template")).not.toBeVisible({ timeout: 5000 });
    await expect(templateRow(page, templateName).getByText("LocalBusiness")).toBeVisible();

    // Delete template
    await templateRow(page, templateName).locator('button:has-text("Delete")').click();

    // Confirm deletion — the modal has "Delete Template" button
    await expect(page.getByText("Delete Template?")).toBeVisible();
    await page.locator('div[style*="position: fixed"]').filter({ hasText: "Delete Template?" }).locator('button:has-text("Delete Template")').click();

    // Verify deleted
    await expect(
      page.getByText(templateName),
      "Template should be removed"
    ).not.toBeVisible();
  });

  test("enable/disable toggle updates state", async ({ page }) => {
    await goToTemplatesTab(page);

    // Create a template
    const templateName = `Toggle-${Date.now()}`;
    await createTemplate(page, templateName, "FlightReservation");

    // Get the specific template row
    const row = templateRow(page, templateName);
    await expect(row).toBeVisible();

    // Verify initially enabled — check the Enabled badge in this specific row
    await expect(row.getByText("Enabled")).toBeVisible();

    // Toggle via the Disable button in the template row
    await row.locator('button:has-text("Disable")').click();
    await expect(row.getByText("Disabled")).toBeVisible();

    // Toggle back via the Enable button
    await row.locator('button:has-text("Enable")').click();
    await expect(row.getByText("Enabled")).toBeVisible();
  });

  test("template list persists after page navigation", async ({ page }) => {
    await goToTemplatesTab(page);

    // Create template
    const templateName = `Persist-${Date.now()}`;
    await createTemplate(page, templateName, "Recipe");

    // Verify template exists
    await expect(templateRow(page, templateName)).toBeVisible();

    // Navigate away (back to canvas) and back to Settings > Templates
    await page.locator(".topbar-brand").click();
    await page.locator("text=+ New Canvas").click();
    await goToTemplatesTab(page);

    // Verify template still present
    await expect(templateRow(page, templateName)).toBeVisible();
  });

  test("settings tab navigation includes Templates", async ({ page }) => {
    // Navigate to Settings page
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);

    // Verify Templates tab exists and is clickable
    const templatesTab = page.locator(".settings-tab", { hasText: "TEMPLATES" });
    await expect(templatesTab).toBeVisible();
    await templatesTab.click();

    // Verify content loaded — the template name input should be visible
    await expect(page.locator('input[placeholder*="Name"]')).toBeVisible();

    // Verify other tabs still present (GENERAL, IDENTITY)
    await expect(page.locator(".settings-tab", { hasText: "GENERAL" })).toBeVisible();
    await expect(page.locator(".settings-tab", { hasText: "IDENTITY" })).toBeVisible();
  });

  test("JSON validation: reject malformed JSON", async ({ page }) => {
    await goToTemplatesTab(page);

    // Try to create with malformed JSON
    const templateName = `BadJSON-${Date.now()}`;
    await page.locator('input[placeholder*="Name"]').fill(templateName);
    await page.locator('input[placeholder*="Schema"]').fill("Recipe");
    await page.locator("textarea").first().fill("{invalid json");
    await page.locator('button:has-text("Create Template")').click();

    // Verify error message appears (the config input validates in real-time)
    await expect(page.getByText("Invalid JSON")).toBeVisible();

    // Template should not be in list
    await expect(page.getByText(templateName)).not.toBeVisible();
  });

  test("validation: reject empty required fields", async ({ page }) => {
    await goToTemplatesTab(page);

    // Try to create with empty name — just fill schema and config
    await page.locator('input[placeholder*="Schema"]').fill("Recipe");
    await page.locator("textarea").first().fill(VALID_CONFIG);

    // Click Create and expect error
    await page.locator('button:has-text("Create Template")').click();
    await expect(page.getByText("required")).toBeVisible();
  });

  test("no console errors when using templates", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        consoleErrors.push(msg.text());
      }
    });

    await goToTemplatesTab(page);

    // Verify the tab loaded without errors
    await expect(page.locator('input[placeholder*="Name"]')).toBeVisible();

    // Verify no console errors
    expect(consoleErrors).toEqual([]);
  });

  test("default templates available in settings", async ({ page }) => {
    await goToTemplatesTab(page);

    // Verify default templates are listed (use .first() for strict mode safety)
    await expect(page.getByText("Default Flight Template").first()).toBeVisible();
    await expect(page.getByText("Default Hotel Template").first()).toBeVisible();

    // Verify they show as enabled
    const enabledBadges = page.getByText("Enabled");
    await expect(enabledBadges.first()).toBeVisible();
  });
});

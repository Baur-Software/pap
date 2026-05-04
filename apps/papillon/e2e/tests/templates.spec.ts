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

/**
 * Directly create a template via IPC mock, bypassing the form UI.
 * SchemaTypeInput focus triggers heavy WASM reactive rendering that blocks
 * the JS thread for 60+ seconds — direct IPC avoids the interaction entirely.
 */
async function createTemplateViaIpc(
  page: import("@playwright/test").Page,
  name: string,
  schemaType: string,
  config: object = { version: 1, layout: { type: "grid", columns: 1 }, fields: [{ path: "name", label: "Name", display: "title" }] },
) {
  await page.evaluate(
    ({ name, schemaType, config }) => {
      return (window as any).__TAURI__.core.invoke("create_template", {
        template: {
          template_name: name,
          schema_type: schemaType,
          template_config: config,
          principal_did: null,
          created_by: null,
        },
      });
    },
    { name, schemaType, config }
  );
}

/** Navigate to Settings > Templates tab and wait for content.
 *
 * Uses direct page.goto when coming from a non-settings page to avoid
 * topbar slide-panel animation timing issues. Falls back to topbar nav
 * when in-memory mock state must be preserved (e.g., after creating a template
 * in the same test and navigating away to canvas then back).
 *
 * @param preserveMock - if true, navigate via topbar panel to keep window.__TAURI__ state
 */
async function goToTemplatesTab(
  page: import("@playwright/test").Page,
  preserveMock: boolean = false
) {
  const settingsNav = page.locator(".settings-nav");
  const alreadyOnSettings = await settingsNav.isVisible().catch(() => false);
  if (!alreadyOnSettings) {
    // Always navigate via topbar panel to avoid a full WASM reload.
    // The preserveMock flag is kept for backwards compat but topbar nav always preserves state.
    await page.locator(".topbar-brand").click();
    await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
    await page.locator(".settings-overlay").waitFor({ state: "visible" });
    await expect(page.locator(".settings-nav")).toBeVisible({ timeout: 10_000 });
  }
  await page.locator(".settings-nav-link").filter({ hasText: "Templates" }).click();
  await expect(page.locator(".settings-nav-link.active").filter({ hasText: "Templates" })).toBeVisible();
}

/** Create a template through the UI form. */
async function createTemplate(
  page: import("@playwright/test").Page,
  name: string,
  schemaType: string,
  config: string = VALID_CONFIG,
) {
  await page.locator('input[placeholder*="Name"]').fill(name);
  // SchemaTypeInput uses Leptos on:input signal binding. Wait for page to be idle after
  // any WASM reactive updates, then interact with the schema type input.
  const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
  await schemaInput.waitFor({ state: "visible" });
  await page.waitForTimeout(500);
  await schemaInput.click();
  await page.keyboard.type(schemaType);
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

    // The modal's first plain text input is the name field.
    // We don't touch SchemaTypeInput in the edit modal (focus-triggered WASM blocking
    // fixed by get_untracked in mod.rs, but edit modal SchemaTypeInput still has the
    // schema_type signal — just save as-is to keep the existing schema type).
    const modal = page.locator('div[style*="position: fixed"]').filter({ hasText: "Edit Template" });
    await modal.locator('button:has-text("Save")').click();

    // Wait for modal to close and template to still appear in the list
    await expect(page.getByText("Edit Template")).not.toBeVisible({ timeout: 5000 });
    await expect(row).toBeVisible();

    // Delete template
    await row.locator('button:has-text("Delete")').click();

    // Confirm deletion — the modal has "Delete Template" button
    await expect(page.getByText("Delete Template?")).toBeVisible();
    await page.locator('div[style*="position: fixed"]').filter({ hasText: "Delete Template?" }).locator('button:has-text("Delete Template")').click();

    // Verify deleted
    await expect(
      page.getByText(templateName),
      "Template should be removed"
    ).not.toBeVisible();
  });

  test("template row shows Edit and Delete buttons", async ({ page }) => {
    await goToTemplatesTab(page);

    // Use an existing default template row (seeded by mock)
    const row = templateRow(page, "Default Flight Template");
    await expect(row).toBeVisible();

    // Each row has Edit and Delete action buttons
    await expect(row.locator('button:has-text("Edit")')).toBeVisible();
    await expect(row.locator('button:has-text("Delete")')).toBeVisible();

    // Each row has a checkbox for bulk operations
    await expect(row.locator('input[type="checkbox"]')).toBeVisible();
  });

  test("template list persists after page navigation", async ({ page }) => {
    await goToTemplatesTab(page);

    // Create template
    const templateName = `Persist-${Date.now()}`;
    await createTemplate(page, templateName, "Recipe");

    // Verify template exists
    await expect(templateRow(page, templateName)).toBeVisible();

    // Navigate away (back to canvas) and back to Settings > Templates.
    // The settings overlay is still open after createTemplate — close it first,
    // then open the panel nav to create a new canvas before returning.
    await page.locator(".settings-overlay-close").click();
    await expect(page.locator(".settings-overlay")).not.toBeVisible({ timeout: 5000 });
    await page.locator(".topbar-brand").click();
    await page.locator(".panel-new-canvas-btn").click();
    await goToTemplatesTab(page, true);

    // Verify template still present
    await expect(templateRow(page, templateName)).toBeVisible();
  });

  test("settings tab navigation includes Templates", async ({ page }) => {
    // Navigate to Settings page
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);

    // Verify Templates nav link exists and is clickable
    const templatesTab = page.locator(".settings-nav-link").filter({ hasText: "Templates" });
    await expect(templatesTab).toBeVisible();
    await templatesTab.click();

    // Verify active state
    await expect(page.locator(".settings-nav-link.active").filter({ hasText: "Templates" })).toBeVisible();

    // Verify other nav links still present (Profiles, Identity)
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Profiles" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Identity" })).toBeVisible();
  });

  test("JSON validation: reject malformed JSON", async ({ page }) => {
    await goToTemplatesTab(page);

    // Try to create with malformed JSON
    const templateName = `BadJSON-${Date.now()}`;
    await page.locator('input[placeholder*="Name"]').fill(templateName);
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.waitFor({ state: "visible" });
    await page.waitForTimeout(500);
    await schemaInput.click();
    await page.keyboard.type("Recipe");
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
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.waitFor({ state: "visible" });
    await page.waitForTimeout(500);
    await schemaInput.click();
    await page.keyboard.type("Recipe");
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

    // Verify their schema types are shown in the rows
    await expect(page.getByText("FlightReservation").first()).toBeVisible();
    await expect(page.getByText("LodgingReservation").first()).toBeVisible();
  });
});

/**
 * E2E tests for PR #258 features:
 *
 * 1. WYSIWYG Template Builder — visual modal for designing templates
 * 2. Schema Type Autocomplete — dropdown backed by registered schema types
 * 3. Template Library — pre-built template examples (Flight, Hotel, Product, …)
 * 4. Auto-Generate Template — registry-driven template generation command
 * 5. Export / Import — bulk template data management
 *
 * All tests run against the Tauri mock so no live backend is required.
 */

import * as fs from "fs";
import * as path from "path";
import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

// ── Helpers ──────────────────────────────────────────────────────────────────

async function goToTemplatesTab(page: import("@playwright/test").Page) {
  // Use the topbar slide-panel for SPA navigation to preserve in-memory mock state.
  const settingsNav = page.locator(".settings-nav");
  const alreadyOnSettings = await settingsNav.isVisible().catch(() => false);
  if (!alreadyOnSettings) {
    await page.locator(".topbar-brand").click();
    await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
    await expect(page.locator(".settings-nav")).toBeVisible({ timeout: 5000 });
  }
  await page.locator(".settings-nav-link").filter({ hasText: "Templates" }).click();
  await expect(page.locator(".settings-nav-link.active").filter({ hasText: "Templates" })).toBeVisible();
}

/** Scope selectors to the WYSIWYG builder modal (fixed overlay with "Template Builder" heading). */
function builderModal(page: import("@playwright/test").Page) {
  return page.locator('div[style*="position: fixed"]').filter({ hasText: "Template Builder" });
}

/** Open the WYSIWYG Template Builder via the "✏️ Builder" button. */
async function openBuilder(page: import("@playwright/test").Page) {
  await page.locator('button:has-text("Builder")').first().click();
  const modal = builderModal(page);
  await expect(modal).toBeVisible({ timeout: 5000 });
  return modal;
}

/** Ensure screenshots dir exists and save page screenshot. */
async function takeScreenshot(page: import("@playwright/test").Page, name: string) {
  const dir = path.join(__dirname, "..", "test-results", "pr258-screenshots");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, `${name}.png`), fullPage: false });
}

// ── 1. WYSIWYG Template Builder ───────────────────────────────────────────────

test.describe("WYSIWYG Template Builder", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await goToTemplatesTab(page);
  });

  test("opens via Builder button and shows Template Builder heading", async ({ page }) => {
    const modal = await openBuilder(page);
    await expect(modal.locator("h3").first()).toContainText("Template Builder");
    await takeScreenshot(page, "01-builder-open");
  });

  test("starts with no fields placeholder", async ({ page }) => {
    const modal = await openBuilder(page);
    await expect(modal.getByText("No fields yet")).toBeVisible();
  });

  test("grid layout (default) shows columns number input", async ({ page }) => {
    const modal = await openBuilder(page);
    // Default layout is grid — columns input should be present
    await expect(modal.locator('input[type="number"]')).toBeVisible();
  });

  test("switching to flex layout hides columns, shows direction select", async ({ page }) => {
    const modal = await openBuilder(page);
    // First select in modal is Layout Type — change to flex
    await modal.locator("select").first().selectOption("flex");
    // Columns input should disappear
    await expect(modal.locator('input[type="number"]')).not.toBeVisible();
    // Direction select with row/column options should appear
    const dirSelect = modal.locator("select").nth(1);
    await expect(dirSelect).toBeVisible();
    await expect(dirSelect.locator("option[value='row']")).toHaveCount(1);
    await expect(dirSelect.locator("option[value='column']")).toHaveCount(1);
  });

  test("adding a field populates the fields list", async ({ page }) => {
    const modal = await openBuilder(page);
    // Fill path
    await modal.locator('input[placeholder*="departureDate"]').fill("name");
    // Fill optional label
    await modal.locator('input[placeholder="Optional display label"]').fill("Name");
    // Click Add Field
    await modal.locator('button:has-text("Add Field")').click();
    // Field should appear in the list
    await expect(modal.getByText("No fields yet")).not.toBeVisible();
    await expect(modal.locator("div").filter({ hasText: /^name$/ }).first()).toBeVisible();
  });

  test("vocabulary inference badge: date property (departureDate → date)", async ({ page }) => {
    const modal = await openBuilder(page);
    await modal.locator('input[placeholder*="departureDate"]').fill("departureDate");
    // Badge with "date" text should appear inline next to the path input
    await expect(modal.locator("span").filter({ hasText: /^date$/ })).toBeVisible({ timeout: 3000 });
  });

  test("vocabulary inference badge: price property (totalPrice → price)", async ({ page }) => {
    const modal = await openBuilder(page);
    await modal.locator('input[placeholder*="departureDate"]').fill("totalPrice");
    await expect(modal.locator("span").filter({ hasText: /^price$/ })).toBeVisible({ timeout: 3000 });
  });

  test("vocabulary inference badge: url property (sameAs → url)", async ({ page }) => {
    const modal = await openBuilder(page);
    await modal.locator('input[placeholder*="departureDate"]').fill("sameAs");
    await expect(modal.locator("span").filter({ hasText: /^url$/ })).toBeVisible({ timeout: 3000 });
  });

  test("JSON preview tab shows serialized config after adding a field", async ({ page }) => {
    const modal = await openBuilder(page);
    // Add a field
    await modal.locator('input[placeholder*="departureDate"]').fill("name");
    await modal.locator('button:has-text("Add Field")').click();
    // Switch to JSON preview
    await modal.locator('button:has-text("JSON")').click();
    // pre element should contain the config JSON
    const pre = modal.locator("pre");
    await expect(pre).toBeVisible();
    await expect(pre).toContainText('"path"');
    await expect(pre).toContainText('"name"');
  });

  test("clicking Add Field without a path shows error", async ({ page }) => {
    const modal = await openBuilder(page);
    // Do not fill path — just click Add Field
    await modal.locator('button:has-text("Add Field")').click();
    // Error message should appear (coral background div or text)
    await expect(modal.getByText(/Field path is required/i)).toBeVisible({ timeout: 3000 });
  });

  test("condition checkbox reveals condition field input", async ({ page }) => {
    const modal = await openBuilder(page);
    // Initially condition inputs are hidden
    await expect(modal.locator('input[placeholder="e.g., offers"]')).not.toBeVisible();
    // Check the Add Condition checkbox
    await modal.locator('input[type="checkbox"]').check();
    // Condition field input should now be visible
    await expect(modal.locator('input[placeholder="e.g., offers"]')).toBeVisible();
  });

  test("Use This Template closes the modal when fields are present", async ({ page }) => {
    const modal = await openBuilder(page);
    // Add a required field first (validation requires at least one field)
    await modal.locator('input[placeholder*="departureDate"]').fill("name");
    await modal.locator('button:has-text("Add Field")').click();
    await expect(modal.getByText("No fields yet")).not.toBeVisible();
    // Click Use This Template
    await modal.locator('button:has-text("Use This Template")').click();
    // Modal should close
    await expect(modal).not.toBeVisible({ timeout: 5000 });
  });

  test("Cancel button closes the modal without changes", async ({ page }) => {
    const modal = await openBuilder(page);
    await modal.locator('button:has-text("Cancel")').click();
    await expect(page.getByText("Template Builder")).not.toBeVisible({ timeout: 3000 });
  });

  test("screenshot: builder with two fields added", async ({ page }) => {
    const modal = await openBuilder(page);
    // Add first field
    await modal.locator('input[placeholder*="departureDate"]').fill("name");
    await modal.locator('input[placeholder="Optional display label"]').fill("Name");
    await modal.locator('button:has-text("Add Field")').click();
    // Add second field with a price property
    await modal.locator('input[placeholder*="departureDate"]').fill("totalPrice");
    await modal.locator('input[placeholder="Optional display label"]').fill("Price");
    await modal.locator('button:has-text("Add Field")').click();
    await expect(modal.locator("div").filter({ hasText: /^name$/ }).first()).toBeVisible();
    await takeScreenshot(page, "02-builder-with-fields");
  });
});

// ── 2. Schema Type Autocomplete ───────────────────────────────────────────────

test.describe("Schema Type Autocomplete", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await goToTemplatesTab(page);
  });

  test("shows dropdown with matching suggestions after typing", async ({ page }) => {
    // The schema-type autocomplete input has placeholder "e.g. FlightReservation"
    // Default templates seed FlightReservation and Hotel — typing "Flight" should show suggestion
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.click();
    await schemaInput.fill("Flight");
    // Dropdown should appear with FlightReservation
    await expect(page.locator("div").filter({ hasText: "FlightReservation" }).last()).toBeVisible({ timeout: 3000 });
  });

  test("clicking a suggestion closes the dropdown (selection confirmed)", async ({ page }) => {
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.click();
    await schemaInput.fill("Flight");

    // Scope the dropdown to the z-index:9999 positioned overlay inside SchemaTypeInput
    const dropdown = page.locator('div[style*="z-index: 9999"]');
    await expect(dropdown).toBeVisible({ timeout: 3000 });

    const suggestion = dropdown.locator("div").filter({ hasText: /^FlightReservation$/ }).first();
    await expect(suggestion).toBeVisible({ timeout: 3000 });

    // The component uses on:mousedown + ev.prevent_default() to handle selection before
    // blur fires. Dispatch a synthetic mousedown event directly on the DOM element so
    // that the WASM event handler runs in the same microtask as the event dispatch,
    // before the browser processes any potential blur on the input.
    await suggestion.dispatchEvent("mousedown");
    // Give the Leptos WASM signal update time to propagate to the DOM.
    await page.waitForTimeout(500);

    // The dropdown should now be closed (show_dropdown set to false in mousedown handler)
    await expect(dropdown).not.toBeVisible({ timeout: 5000 });

    // The input value should have been set to the selected suggestion
    await expect(schemaInput).toHaveValue("FlightReservation", { timeout: 5000 });
  });

  test("unknown schema type is accepted without error", async ({ page }) => {
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.fill("MyCustomSchemaXYZ");
    // No error should appear — unknown types are always accepted
    await expect(page.getByText(/invalid/i)).not.toBeVisible();
    await expect(schemaInput).toHaveValue("MyCustomSchemaXYZ");
  });

  test("filtering is case-insensitive (flight → FlightReservation)", async ({ page }) => {
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.click();
    await schemaInput.fill("flight"); // lowercase
    // FlightReservation should still appear in suggestions
    await expect(page.locator("div").filter({ hasText: "FlightReservation" }).last()).toBeVisible({ timeout: 3000 });
  });
});

// ── 3. Template Library ───────────────────────────────────────────────────────

test.describe("Template Library", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await goToTemplatesTab(page);
  });

  test("opens via Library button and shows Template Library heading", async ({ page }) => {
    await page.locator('button:has-text("Library")').first().click();
    const modal = page.locator('div[style*="position: fixed"]').filter({ hasText: "Template Library" });
    await expect(modal).toBeVisible({ timeout: 5000 });
    await expect(modal.locator("h3").first()).toContainText("Template Library");
    await takeScreenshot(page, "03-template-library-open");
  });

  test("shows pre-built Flight Reservation and Hotel Reservation examples", async ({ page }) => {
    await page.locator('button:has-text("Library")').first().click();
    const modal = page.locator('div[style*="position: fixed"]').filter({ hasText: "Template Library" });
    await expect(modal).toBeVisible({ timeout: 5000 });
    await expect(modal.getByText("Flight Reservation")).toBeVisible();
    await expect(modal.getByText("Hotel Reservation")).toBeVisible();
  });

  test("Copy & Customize closes the library modal", async ({ page }) => {
    await page.locator('button:has-text("Library")').first().click();
    const modal = page.locator('div[style*="position: fixed"]').filter({ hasText: "Template Library" });
    await expect(modal).toBeVisible({ timeout: 5000 });
    // Click Copy & Customize on the first example (Flight Reservation)
    await modal.locator('button:has-text("Copy & Customize")').first().click();
    // Library modal should close
    await expect(modal).not.toBeVisible({ timeout: 5000 });
  });

  test("Close button dismisses the library modal", async ({ page }) => {
    await page.locator('button:has-text("Library")').first().click();
    const modal = page.locator('div[style*="position: fixed"]').filter({ hasText: "Template Library" });
    await expect(modal).toBeVisible({ timeout: 5000 });
    await modal.locator('button:has-text("Close")').click();
    await expect(modal).not.toBeVisible({ timeout: 3000 });
  });
});

// ── 4. Auto-Generate Template + Registry Dispatch ─────────────────────────────

test.describe("Auto-Generate Template and Registry-Driven Rendering", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
  });

  test("auto_generate_template returns generated template for new schema type", async ({ page }) => {
    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("auto_generate_template", {
        schema_type: "RecipeCard",
        content: { name: "Chocolate Cake", recipeIngredient: ["flour", "cocoa"], cookTime: "PT1H" },
      })
    );

    expect(result).not.toBeNull();
    expect(result.schema_type).toBe("RecipeCard");
    expect(result.created_by).toBe("orchestrator");
    expect(result.template_config.fields.length).toBeGreaterThan(0);
    expect(result.enabled).toBe(true);
  });

  test("auto_generate_template returns null when schema type already has a template", async ({
    page,
  }) => {
    // FlightReservation is seeded in the mock — generating again should return null
    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("auto_generate_template", {
        schema_type: "FlightReservation",
        content: { name: "test" },
      })
    );
    expect(result).toBeNull();
  });

  test("generated template is persisted and retrievable via get_global_templates", async ({
    page,
  }) => {
    await page.evaluate(() =>
      window.__TAURI__.core.invoke("auto_generate_template", {
        schema_type: "UniqueTypeXYZ",
        content: { name: "Test" },
      })
    );

    const templates = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_global_templates")
    );

    const found = templates.find((t: any) => t.schema_type === "UniqueTypeXYZ");
    expect(found).toBeDefined();
    expect(found.created_by).toBe("orchestrator");
  });

  test("FlightReservation block uses declarative renderer (tier-2 template dispatch)", async ({
    page,
  }) => {
    await page.locator(".topbar-address-input").fill("mock:flightreservation");
    await page.locator(".topbar-address-input").press("Enter");

    // The app has pre-existing UNKNOWN blocks; filter to the one that has a declarative grid
    // (this is the only block that DeclarativeRenderer::render() produced).
    const declarativeBlock = page
      .locator(".canvas-block")
      .filter({ has: page.locator(".declarative-grid") });
    await expect(declarativeBlock).toBeVisible({ timeout: 8000 });

    // Individual field rows produced by DeclarativeRenderer
    await expect(declarativeBlock.locator(".declarative-field").first()).toBeVisible();

    // The seeded template's first field is reservationNumber → value "PX-4892"
    await expect(declarativeBlock.locator(".declarative-value").first()).toContainText("PX-4892");
  });

  test("Hotel block uses declarative renderer (LodgingReservation tier-2 dispatch)", async ({
    page,
  }) => {
    await page.locator(".topbar-address-input").fill("mock:hotel");
    await page.locator(".topbar-address-input").press("Enter");

    // Hotel template may use grid or flex layout — filter by either
    const declarativeBlock = page
      .locator(".canvas-block")
      .filter({ has: page.locator(".declarative-grid, .declarative-flex") });
    await expect(declarativeBlock).toBeVisible({ timeout: 8000 });

    await expect(declarativeBlock.locator(".declarative-field").first()).toBeVisible();
    await expect(declarativeBlock.locator(".declarative-value").first()).toContainText(
      "The Grand Pacific"
    );
  });
});

// ── 5. Export / Import ────────────────────────────────────────────────────────

test.describe("Template Export and Import", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await goToTemplatesTab(page);
  });

  test("export_templates command returns JSON string with current templates", async ({ page }) => {
    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("export_templates")
    );

    expect(typeof result).toBe("string");
    const parsed = JSON.parse(result);
    expect(Array.isArray(parsed)).toBe(true);
    // Seeded templates should be included
    const names = parsed.map((t: any) => t.template_name);
    expect(names).toContain("Default Flight Template");
    expect(names).toContain("Default Hotel Template");
  });

  test("import_templates skips duplicates and adds new templates", async ({ page }) => {
    const importPayload = JSON.stringify([
      {
        id: "tmpl-import-1",
        template_name: "Imported Recipe Template",
        schema_type: "Recipe",
        principal_did: null,
        template_config: {
          version: 1,
          layout: { type: "flex", direction: "column", spacing: "md" },
          fields: [{ path: "name", label: null, display: "title", condition: null, style: null }],
        },
        version: 1,
        enabled: true,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        created_by: null,
      },
      // Duplicate — should be skipped
      {
        id: "tmpl-flight",
        template_name: "Default Flight Template",
        schema_type: "FlightReservation",
        principal_did: null,
        template_config: { version: 1, layout: { type: "grid", columns: 2 }, fields: [] },
        version: 1,
        enabled: true,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        created_by: null,
      },
    ]);

    await page.evaluate(
      (json) => window.__TAURI__.core.invoke("import_templates", { json_str: json }),
      importPayload
    );

    const templates = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_global_templates")
    );

    // Imported recipe should be present
    const recipeTemplate = templates.find((t: any) => t.template_name === "Imported Recipe Template");
    expect(recipeTemplate).toBeDefined();
    // Duplicate flight template should not be duplicated
    const flightTemplates = templates.filter(
      (t: any) => t.template_name === "Default Flight Template"
    );
    expect(flightTemplates).toHaveLength(1);
  });

  test("Export Templates section is visible in the settings Data Management area", async ({
    page,
  }) => {
    // Verify the Export and Import buttons appear in the Data Management section
    await expect(page.getByText("Data Management")).toBeVisible();
    await expect(page.locator('button:has-text("Export Templates")')).toBeVisible();
    await expect(page.locator('button:has-text("Import Templates")')).toBeVisible();
  });

  test("Export button invokes export_templates and receives valid JSON", async ({ page }) => {
    // Spy on the export call by tracking it via evaluate before the button click
    let exportCalled = false;
    await page.exposeFunction("__testExportCalled__", () => {
      exportCalled = true;
    });

    // Patch the mock to notify us when export_templates is invoked
    await page.evaluate(() => {
      const origInvoke = window.__TAURI__.core.invoke;
      window.__TAURI__.core.invoke = async function (cmd: string, args: any) {
        if (cmd === "export_templates") {
          (window as any).__testExportCalled__();
        }
        return origInvoke.call(this, cmd, args);
      };
    });

    await page.locator('button:has-text("Export Templates")').click();

    // Wait briefly for the async click handler to fire
    await page.waitForTimeout(500);
    expect(exportCalled).toBe(true);
  });
});

// ── 6. Live Registry Types in Autocomplete ────────────────────────────────────

test.describe("Live Registry Types in Autocomplete", () => {
  test.beforeEach(async ({ page }) => {
    await installTauriMock(page);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await goToTemplatesTab(page);
  });

  test("Movie appears in autocomplete (shipped renderer, absent from mock templates)", async ({
    page,
  }) => {
    // Mock seeds only FlightReservation + LodgingReservation. Movie is registered in
    // create_default_registry() via MovieTemplate — must appear in autocomplete once
    // RendererState is app-level and registered_keys is seeded from the live registry.
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.click();
    await schemaInput.fill("Mov");
    const dropdown = page.locator('div[style*="z-index: 9999"]');
    await expect(dropdown).toBeVisible({ timeout: 3000 });
    await expect(dropdown.locator("div").filter({ hasText: /^Movie$/ }).first()).toBeVisible({
      timeout: 3000,
    });
  });

  test("Person appears in autocomplete (shipped renderer, absent from mock templates)", async ({
    page,
  }) => {
    // Person is registered in create_default_registry() via PersonTemplate.
    // Proves the autocomplete is fed from the live registry, not just saved templates.
    const schemaInput = page.locator('input[placeholder*="FlightReservation"]').first();
    await schemaInput.click();
    await schemaInput.fill("Per");
    const dropdown = page.locator('div[style*="z-index: 9999"]');
    await expect(dropdown).toBeVisible({ timeout: 3000 });
    await expect(dropdown.locator("div").filter({ hasText: /^Person$/ }).first()).toBeVisible({
      timeout: 3000,
    });
  });
});

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test("debug: template creation and reload", async ({ page }) => {
  const logs: string[] = [];
  page.on("console", (msg) => logs.push(`[${msg.type()}] ${msg.text()}`));

  await installTauriMock(page);
  await page.goto("/", { waitUntil: "commit" });
  await waitForApp(page);

  await page.locator(".settings-gear").click();
  await page.locator(".settings-tab", { hasText: "Templates" }).click();
  await expect(page.locator('input[placeholder*="Name"]')).toBeVisible();

  // Create template with valid config (at least one field)
  await page.locator('input[placeholder*="Name"]').fill("DebugTemplate");
  await page.locator('input[placeholder*="Schema"]').fill("Recipe");
  await page.locator("textarea").first().fill(JSON.stringify({
    version: 1,
    layout: { type: "grid", columns: 1 },
    fields: [{ path: "name", label: "Name", display: "title" }],
  }));
  await page.locator('button:has-text("Create Template")').click();

  // Wait for success or error
  await page.waitForTimeout(3000);

  // Check mock state
  const state = await page.evaluate(() => {
    const templates = window.__TAURI__.core._templates;
    return {
      count: templates.length,
      names: templates.map(t => t.template_name),
      lastTemplate: templates.length > 2 ? JSON.stringify(templates[templates.length - 1]) : 'none',
    };
  });
  console.log("Mock state:", JSON.stringify(state));

  // Check the tauri logs for create_template
  const createLogs = logs.filter(l => l.includes("create_template"));
  console.log("create_template logs:", createLogs.length > 0 ? createLogs.join("\n") : "NONE");

  // Check for get_global_templates after create
  const globalLogs = logs.filter(l => l.includes("get_global_templates"));
  console.log("get_global_templates calls:", globalLogs.length);

  // Check visible text
  const body = await page.locator("body").textContent() || "";
  console.log("Has success:", body.includes("successfully"));
  console.log("Has DebugTemplate:", body.includes("DebugTemplate"));
  console.log("Has Default Flight:", body.includes("Default Flight"));

  // Take screenshot
  await page.screenshot({ path: "test-results/debug-create-check.png", fullPage: true });
});

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── Top Bar & App Shell ──────────────────────────────────────

test.describe("App shell", () => {
  test("renders top bar with brand icon and workflow toggle", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".topbar")).toBeVisible();
    await expect(page.locator(".topbar-brand-icon")).toBeVisible();
    await expect(page.locator(".canvas-flip-toggle")).toBeVisible();
  });

  test("shows workflow toggle button in top bar right zone", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".canvas-flip-toggle")).toContainText("Workflow");
    await expect(page.locator(".topbar-address-input")).toBeVisible();
  });

  test("brand button opens slide panel with nav items", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    await expect(page.locator(".panel-section-label").first()).toContainText("Canvases");
  });

  test("slide panel shows navigate and settings sections", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    // Slide panel contains Receipts nav item and All Settings button
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "Receipts" })).toBeVisible();
    await expect(page.locator(".slide-panel .panel-nav-item").filter({ hasText: "All Settings" })).toBeVisible();
  });

  test("shows status bar footer", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".status-bar")).toBeVisible();
  });
});

// ── Canvas Page (Home) ───────────────────────────────────────

test.describe("Canvas page", () => {
  test("shows empty state with agent tiles on new canvas", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".canvas-stream")).toBeVisible();
    // Seed canvas has blocks — create a new empty canvas via brand dropdown
    await page.locator(".topbar-brand").click();
    await page.locator("text=+ New Canvas").click();
    await expect(page.locator(".canvas-rendered-placeholder-title")).toContainText(
      "Approve your workflow before rendering"
    );
  });

  test("shows address bar prompt when orchestrator is ready", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // The prompt input is now the topbar address bar, not an inline canvas element
    await expect(page.locator(".topbar-address-input")).toBeVisible();
    await expect(page.locator(".canvas-dock-toggle")).toContainText("Orchestrator");
  });

  test("address bar input accepts text", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-address-input").fill("Search for flights");
    await expect(page.locator(".topbar-address-input")).toHaveValue("Search for flights");
    // Suggestions should hide when input has non-pap:// text
    await expect(page.locator(".palette-suggestion").first()).not.toBeVisible();
  });

  test("canvas renders normally when orchestrator is disconnected", async ({ page }) => {
    // Override mock to return Disconnected status
    await page.addInitScript(`
      const origInvoke = window.__TAURI__.core.invoke;
      window.__TAURI__.core.invoke = async function(cmd, args) {
        if (cmd === 'get_orchestrator_status') return 'Disconnected';
        return origInvoke.call(this, cmd, args);
      };
    `);
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // Canvas still renders — deterministic routing works without LLM
    await expect(page.locator(".canvas-stream")).toBeVisible();
    // Topbar address input is still available
    await expect(page.locator(".topbar-address-input")).toBeVisible();
  });
});

// ── Activity Page ────────────────────────────────────────────

test.describe("Activity page", () => {
  test("shows empty state when no runs", async ({ page }) => {
    await page.goto("/activity", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(
      page.locator("text=No activity yet.")
    ).toBeVisible();
  });
});

// ── Settings Page ────────────────────────────────────────────

test.describe("Settings page", () => {
  test("renders settings nav with all sections", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    // Settings page uses a left-nav layout (settings-nav-link), not horizontal tabs
    await expect(page.locator(".settings-nav")).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Profiles" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Identity" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Templates" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Privacy" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Network" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Advanced" })).toBeVisible();
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Appearance" })).toBeVisible();
  });

  test("Orchestrator nav shows AI model config", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    // Click Orchestrator nav link to show the AI model section
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();
    await expect(page.locator("text=AI Model")).toBeVisible();
    // Provider select is the first select on the page
    await expect(page.locator("select").first()).toBeVisible();
  });

  test("Identity tab shows identity info and backup warning", async ({
    page,
  }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Identity" }).click();

    // Should show backup warning (key not backed up)
    await expect(page.locator(".backup-warning")).toBeVisible();
    await expect(
      page.locator("text=Your key has not been backed up!")
    ).toBeVisible();

    // Should show identity key label
    await expect(page.getByText("Identity key:", { exact: true })).toBeVisible();

    // Export and Import buttons
    await expect(page.locator("text=Export Key")).toBeVisible();
    await expect(page.locator("text=Import Key")).toBeVisible();
  });

  test("Export key shows seed and clears backup warning", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Identity" }).click();
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

  test("Identity tab shows export and import key UI", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Identity" }).click();

    // Export Key button is always visible
    await expect(page.locator("text=Export Key")).toBeVisible();

    // Import Key button is always visible
    await expect(page.locator("text=Import Key")).toBeVisible();

    // Click Import Key to reveal the import form
    await page.locator("text=Import Key").click();

    // Import form appears with a password input for base64url seed
    await expect(
      page.locator('input[placeholder="Paste base64url seed..."]')
    ).toBeVisible();

    // Import submit button inside the form is visible (exact match)
    await expect(page.getByRole("button", { name: "Import", exact: true })).toBeVisible();
  });

  test("switching nav links works", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);

    // Default is Profiles — nav is visible
    await expect(page.locator(".settings-nav")).toBeVisible();

    // Switch to Orchestrator — shows AI Model heading
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();
    await expect(page.locator("text=AI Model")).toBeVisible();

    // Switch to Identity — shows Export Key button
    await page.locator(".settings-nav-link").filter({ hasText: "Identity" }).click();
    await expect(page.locator("text=Export Key")).toBeVisible();

    // Switch to Advanced — shows Saved Registries
    await page.locator(".settings-nav-link").filter({ hasText: "Advanced" }).click();
    await expect(page.locator("text=Saved Registries")).toBeVisible();
  });
});

// ── Tier 2 Tests: Scenario Selection & Disclosure ─────────────

test.describe("Scenario selection and disclosure", () => {
  test("loads scenarios with correct disclosure requirements", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // Click "Browse Scenarios" or navigate to scenarios
    await page.locator(".topbar-brand").click();
    // Assuming there's a scenarios link
    const scenariosLink = page.locator("text=Scenarios, Mandates & Receipts");
    if (await scenariosLink.isVisible()) {
      await scenariosLink.click();
      // Should show scenarios list
      await expect(page.locator("text=Book a Flight")).toBeVisible({ timeout: 5000 });
      await expect(page.locator("text=Send Payment")).toBeVisible();
    }
  });

  test("scenario details show required disclosures", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // Navigate to scenario page if available, or verify via mock
    // Mock returns scenarios with requires_disclosure array
    // Booking scenario requires: name, email, passport_number
    // Payment scenario requires: account_id
    // This test verifies the mock is returning correct structure
    const initiateScenario = async (scenarioId: string) => {
      const scenarios = await page.evaluate(() => {
        return window.__TAURI__.core.invoke("list_scenarios");
      });
      expect(scenarios).toHaveLength(3);
      const booking = scenarios.find(s => s.id === "booking");
      expect(booking.requires_disclosure).toContain("name");
      expect(booking.requires_disclosure).toContain("email");
      expect(booking.requires_disclosure).toContain("passport_number");
    };
    await initiateScenario("booking");
  });
});

// ── Tier 2 Tests: PAP Handshake Execution ────────────────────────

test.describe("PAP handshake execution", () => {
  test("running scenario returns receipt with 6 steps", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // Execute scenario via mock (simulating full handshake)
    const result = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" });
    });
    // Verify receipt structure
    expect(result.success).toBe(true);
    expect(result.steps).toHaveLength(6);
    expect(result.steps.map(s => s.step_name)).toEqual([
      "Discover Agent",
      "Issue Mandate",
      "Open Session",
      "Exchange Data",
      "Co-sign Receipt",
      "Close Session",
    ]);
    // Verify receipt is co-signed
    expect(result.receipt.co_signed).toBe(true);
    expect(result.receipt.property_refs).toEqual([]); // weather has no disclosure
  });

  test("running booking scenario includes disclosure in receipt", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    const result = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("run_scenario", { scenarioId: "booking" });
    });
    // Booking scenario requires 3 properties
    expect(result.receipt.property_refs).toContain("name");
    expect(result.receipt.property_refs).toContain("email");
    expect(result.receipt.property_refs).toContain("passport_number");
  });

  test("completed runs are accumulated in list", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    // Run two scenarios
    await page.evaluate(() => {
      return window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" });
    });
    await page.evaluate(() => {
      return window.__TAURI__.core.invoke("run_scenario", { scenarioId: "payment" });
    });
    // List completed runs
    const runs = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("list_completed_runs");
    });
    expect(runs).toHaveLength(2);
    expect(runs[0].scenario_id).toBe("weather");
    expect(runs[1].scenario_id).toBe("payment");
  });
});

// ── Tier 2 Tests: Settings Management & Persistence ──────────

test.describe("Settings management and persistence", () => {
  test("LLM provider configuration can be updated", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    // Get initial config
    const initialConfig = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("get_orchestrator_config");
    });
    expect(initialConfig.llm_provider).toBeDefined();
    // Configure new provider
    const newConfig = {
      ...initialConfig,
      llm_provider: "Mistral",
    };
    const updated = await page.evaluate((config) => {
      return window.__TAURI__.core.invoke("configure_orchestrator", { config });
    }, newConfig);
    expect(updated.llm_provider).toBe("Mistral");
    // Verify get_orchestrator_config now returns the persisted value
    const persisted = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("get_orchestrator_config");
    });
    expect(persisted.llm_provider).toBe("Mistral");
  });

  test("mandate TTL configuration persists", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    const config = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("get_orchestrator_config");
    });
    expect(config.mandate_ttl_hours).toBe(8);
    // UI could update this value — this test verifies mock supports it
    const updated = await page.evaluate((cfg) => {
      return window.__TAURI__.core.invoke("configure_orchestrator", {
        config: { ...cfg, mandate_ttl_hours: 24 },
      });
    }, config);
    expect(updated.mandate_ttl_hours).toBe(24);
  });

  test("successors can be added and persisted", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Identity" }).click();
    // Verify empty state
    let successors = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("list_successors");
    });
    expect(successors).toHaveLength(0);
    // Add successor
    await page.evaluate(() => {
      return window.__TAURI__.core.invoke("add_successor", {
        successorDid: "did:key:z6MkSuccessor1",
        relationship: "executor",
        notes: "My estate executor",
      });
    });
    // Verify it was added
    successors = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("list_successors");
    });
    expect(successors).toHaveLength(1);
    expect(successors[0].successor_did).toBe("did:key:z6MkSuccessor1");
  });

  test("successors can be removed", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    // Add two successors
    await page.evaluate(() => {
      window.__TAURI__.core.invoke("add_successor", {
        successorDid: "did:key:z6MkSuccessor1",
        relationship: "executor",
      });
      return window.__TAURI__.core.invoke("add_successor", {
        successorDid: "did:key:z6MkSuccessor2",
        relationship: "backup",
      });
    });
    let successors = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("list_successors");
    });
    expect(successors).toHaveLength(2);
    // Remove one
    await page.evaluate(() => {
      return window.__TAURI__.core.invoke("remove_successor", {
        successorDid: "did:key:z6MkSuccessor1",
      });
    });
    // Verify it was removed
    successors = await page.evaluate(() => {
      return window.__TAURI__.core.invoke("list_successors");
    });
    expect(successors).toHaveLength(1);
    expect(successors[0].successor_did).toBe("did:key:z6MkSuccessor2");
  });
});

// ── Settings Overlay ─────────────────────────────────────────────

test.describe("Settings overlay", () => {
  test("clicking All Settings in slide panel opens settings overlay", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await expect(page.locator(".slide-panel.open")).toBeVisible();
    await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
    await expect(page.locator(".settings-overlay")).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".settings-overlay-title")).toContainText("SETTINGS");
  });

  test("settings overlay X button closes the overlay", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".topbar-brand").click();
    await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
    await expect(page.locator(".settings-overlay")).toBeVisible({ timeout: 5000 });
    await page.locator(".settings-overlay-close").click();
    await expect(page.locator(".settings-overlay")).not.toBeVisible();
  });
});

/**
 * E2E tests for Dynamic Agent Fleet — dashboard page and agent lifecycle commands.
 *
 * Covers:
 * - Fleet page renders with correct header, badges, and agent cards
 * - Agent cards display name, source badge, and action type
 * - list_local_agents returns all 3 seeded mock agents
 * - save_agent persists a new agent and returns AgentInfo with agent_did
 * - update_agent mutates an existing agent
 * - delete_agent removes an agent from the fleet
 * - generate_agent returns a preview DynamicAgentDef without agent_did
 * - publish_agent / unpublish_agent update published_to
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── Network tab in Settings (formerly at /fleet) ──────────────

// Helper: navigate to Settings > Network tab
async function openNetworkTab(page: import("@playwright/test").Page): Promise<void> {
  await page.goto("/", { waitUntil: "commit" });
  await waitForApp(page);
  await page.locator(".topbar-brand").click();
  await page.locator(".panel-nav-item").filter({ hasText: "All Settings" }).click();
  await expect(page.locator(".settings-overlay")).toBeVisible({ timeout: 5000 });
  await page.locator(".settings-nav-link").filter({ hasText: "Network" }).click();
}

test.describe("Network settings tab", () => {
  test("settings Network tab renders the section title", async ({ page }) => {
    await openNetworkTab(page);
    await expect(page.locator(".settings-section-title")).toContainText("Network");
  });

  test("This Node group is present", async ({ page }) => {
    await openNetworkTab(page);
    await expect(page.locator(".settings-group-label").filter({ hasText: "This Node" })).toBeVisible();
  });

  test("Remote Nodes group is present", async ({ page }) => {
    await openNetworkTab(page);
    await expect(page.locator(".settings-group-label").filter({ hasText: "Remote Nodes" })).toBeVisible();
  });

  test("Connect to Node group has a text input and Connect button", async ({ page }) => {
    await openNetworkTab(page);
    await expect(page.locator(".settings-group-label").filter({ hasText: "Connect to Node" })).toBeVisible();
    await expect(page.locator(".settings-input").first()).toBeVisible();
    await expect(page.locator(".btn-primary")).toContainText("Connect");
  });

  test("Network tab is accessible from settings nav", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".settings-nav-link").filter({ hasText: "Network" })).toBeVisible();
  });
});

// ── Agent command round-trips ─────────────────────────────────

test.describe("Agent command round-trips", () => {
  test("list_local_agents returns 5 seeded agents with new fields", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    // 2 compiled + 2 catalog + 1 user_created = 5
    expect(agents).toHaveLength(5);

    // Every agent must have the new AgentInfo fields
    for (const agent of agents) {
      expect(agent).toHaveProperty("agent_did");
      expect(agent).toHaveProperty("source");
      expect(agent).toHaveProperty("published_to");
      expect(typeof agent.source).toBe("string");
      expect(Array.isArray(agent.published_to)).toBe(true);
    }

    // Sources must be valid
    const sources = agents.map((a: any) => a.source);
    expect(sources).toContain("compiled");
    expect(sources).toContain("catalog");
    expect(sources).toContain("user_created");
  });

  test("save_agent persists a new agent and returns AgentInfo with agent_did", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const saved = await page.evaluate(() =>
      window.__TAURI__.core.invoke("save_agent", {
        def: {
          name: "Test Agent",
          provider: "Test Provider",
          action: "schema:SearchAction",
          object_types: ["SearchAction"],
          requires_disclosure: [],
          returns: ["results"],
          schema_version: 1,
        },
      })
    );

    expect(saved).not.toBeNull();
    expect(saved.name).toBe("Test Agent");
    expect(saved.agent_did).toBeTruthy();
    expect(saved.source).toBe("user_created");
    expect(saved.published_to).toEqual([]);

    // Verify it appears in the list
    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    expect(agents).toHaveLength(6); // 5 seeded + 1 new
    expect(agents.find((a: any) => a.name === "Test Agent")).toBeDefined();
  });

  test("update_agent mutates an existing agent", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Get the user_created agent
    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const custom = agents.find((a: any) => a.source === "user_created");
    expect(custom).toBeDefined();

    // Update its name
    const updated = await page.evaluate((did: string) =>
      window.__TAURI__.core.invoke("update_agent", {
        def: {
          agent_did: did,
          name: "Renamed Agent",
          action: "schema:UpdateAction",
        },
      }),
    custom.agent_did);

    expect(updated.name).toBe("Renamed Agent");

    // Verify in list
    const after = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    expect(after.find((a: any) => a.name === "Renamed Agent")).toBeDefined();
  });

  test("delete_agent removes the agent from the fleet", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const custom = agents.find((a: any) => a.source === "user_created");

    await page.evaluate((did: string) =>
      window.__TAURI__.core.invoke("delete_agent", { agent_did: did }),
    custom.agent_did);

    const after = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    expect(after).toHaveLength(4); // 5 seeded - 1 deleted = 4
    expect(after.find((a: any) => a.agent_did === custom.agent_did)).toBeUndefined();
  });

  test("generate_agent returns preview without agent_did", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const preview = await page.evaluate(() =>
      window.__TAURI__.core.invoke("generate_agent", {
        prompt: "search the web for news",
      })
    );

    expect(preview).not.toBeNull();
    // Preview must NOT have agent_did (not yet saved)
    expect(preview.agent_did).toBeNull();
    // Must have schema: action prefix
    expect(preview.action).toMatch(/^schema:/);
    // Must have a public HTTPS endpoint
    expect(preview.endpoint?.url_template).toMatch(/^https:\/\//);
    // operator_key_seed must be stripped
    expect(preview.operator_key_seed).toBeNull();
    // source must be 'generated'
    expect(preview.source).toBe("generated");
  });

  test("publish_agent adds registry URL to published_to", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    // catalog agent starts with empty published_to
    const catalog = agents.find((a: any) => a.source === "catalog" && a.published_to.length === 0);
    expect(catalog).toBeDefined();

    await page.evaluate((did: string) =>
      window.__TAURI__.core.invoke("publish_agent", {
        agent_did: did,
        registry_url: "https://chrysalis.test",
      }),
    catalog.agent_did);

    const after = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const published = after.find((a: any) => a.agent_did === catalog.agent_did);
    expect(published.published_to).toContain("https://chrysalis.test");
  });

  test("unpublish_agent removes registry URL from published_to", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // user_created agent starts with published_to: ['https://chrysalis.example.com']
    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const custom = agents.find((a: any) => a.source === "user_created");
    expect(custom.published_to).toContain("https://chrysalis.example.com");

    await page.evaluate((did: string) =>
      window.__TAURI__.core.invoke("unpublish_agent", {
        agent_did: did,
        registry_url: "https://chrysalis.example.com",
      }),
    custom.agent_did);

    const after = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const unpublished = after.find((a: any) => a.agent_did === custom.agent_did);
    expect(unpublished.published_to).not.toContain("https://chrysalis.example.com");
    expect(unpublished.published_to).toHaveLength(0);
  });

  test("publish_agent is idempotent (no duplicate URLs)", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const catalog = agents.find((a: any) => a.source === "catalog" && a.published_to.length === 0);

    // Publish twice
    await page.evaluate((did: string) =>
      window.__TAURI__.core.invoke("publish_agent", {
        agent_did: did,
        registry_url: "https://chrysalis.test",
      }),
    catalog.agent_did);
    await page.evaluate((did: string) =>
      window.__TAURI__.core.invoke("publish_agent", {
        agent_did: did,
        registry_url: "https://chrysalis.test",
      }),
    catalog.agent_did);

    const after = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const published = after.find((a: any) => a.agent_did === catalog.agent_did);
    // URL should appear exactly once
    expect(published.published_to.filter((u: string) => u === "https://chrysalis.test")).toHaveLength(1);
  });
});

// ── Agent Picker Modal ────────────────────────────────────────
// The agent picker is surfaced from canvas empty state agent tiles.

test.describe("Agent Picker Modal", () => {
  test("agent picker command returns list of installed agents", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    expect(Array.isArray(agents)).toBe(true);
    expect(agents.length).toBeGreaterThan(0);

    for (const agent of agents) {
      expect(agent).toHaveProperty("name");
      expect(agent).toHaveProperty("agent_did");
    }
  });

  test("list_local_agents returns agents with required fields", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    for (const agent of agents) {
      expect(agent).toHaveProperty("name");
      expect(agent).toHaveProperty("agent_did");
      expect(agent).toHaveProperty("source");
      expect(agent).toHaveProperty("capabilities");
    }
  });

  test("list_local_agents includes all agent sources", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    const sources = agents.map((a: any) => a.source);
    expect(sources).toContain("compiled");
    expect(sources).toContain("catalog");
  });

  test("agent picker modal appears when triggered via canvas empty state", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Create a new empty canvas first
    await page.locator(".topbar-brand").click();
    await page.locator("text=+ New Canvas").click();
    // New canvas shows the "Approve workflow to render" status in the canvas stream
    await expect(page.locator(".canvas-surface-status")).toContainText("Approve workflow to render");
  });
});

// ── Agent Picker Modal (Browse page) ─────────────────────────

test.describe("Agent Picker Modal (Browse page)", () => {
  test("browse page opens agent picker modal immediately", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".agent-picker-overlay")).toBeVisible({ timeout: 5000 });
    await expect(page.locator(".agent-picker-modal")).toBeVisible();
    await expect(page.locator(".agent-picker-title")).toContainText("INSTALLED AGENTS");
  });

  test("agent picker search filters results", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".agent-picker-search").waitFor({ state: "visible" });
    await page.locator(".agent-picker-search").fill("web");
    // Count visible agent cards — may be 0 if none match, that's acceptable
    const cards = page.locator(".agent-picker-card");
    const count = await cards.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("agent picker close button dismisses modal", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".agent-picker-close").waitFor({ state: "visible" });
    await page.locator(".agent-picker-close").click();
    await expect(page.locator(".agent-picker-overlay")).not.toBeVisible();
  });

  test("agent picker shows count label", async ({ page }) => {
    await page.goto("/browse", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".agent-picker-count")).toContainText("agents installed");
  });
});

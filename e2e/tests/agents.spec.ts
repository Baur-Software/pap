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

// ── Chrysalis Network page rendering (mounted at /fleet) ──────

test.describe("Agent fleet page", () => {
  test("renders Chrysalis Network header title and subtitle", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".chrysalis-header-title")).toContainText(
      "CHRYSALIS NETWORK"
    );
    await expect(page.locator(".chrysalis-header-subtitle")).toBeVisible();
  });

  test("renders NETWORK NODES section label", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".chrysalis-section-label")).toContainText("NETWORK NODES");
  });

  test("local node row is always present", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const localRow = page.locator(".chrysalis-node-row.local");
    await expect(localRow).toBeVisible();
    await expect(localRow.locator(".chrysalis-node-url")).toContainText("pap://local");
    await expect(localRow.locator(".chrysalis-node-tag.local")).toContainText("LOCAL");
  });

  test("local node row has BROWSE link", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const localRow = page.locator(".chrysalis-node-row.local");
    await expect(localRow.locator(".chrysalis-node-action")).toContainText("BROWSE →");
  });

  test("connect form is present with correct input placeholder", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".chrysalis-connect")).toBeVisible();
    await expect(page.locator(".chrysalis-connect-input")).toBeVisible();
    await expect(page.locator(".chrysalis-connect-btn")).toContainText("CONNECT");
  });

  test("THIS NODE identity panel is present", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".chrysalis-panel")).toBeVisible();
    await expect(page.locator(".chrysalis-panel-header")).toContainText("THIS NODE");
  });

  test("agent roster section is present with pills", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const roster = page.locator(".chrysalis-agents");
    await expect(roster).toBeVisible();
    await expect(roster.locator(".chrysalis-agents-title")).toContainText("AGENT ROSTER");
    // compiled and catalog pills are always rendered
    await expect(roster.locator(".chrysalis-pill.compiled")).toBeVisible();
    await expect(roster.locator(".chrysalis-pill.catalog")).toBeVisible();
  });

  test("agent roster toggle caret is visible and clickable", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const toggle = page.locator(".chrysalis-agents-toggle");
    await expect(toggle).toBeVisible();
    // Initial state: collapsed (▼)
    await expect(page.locator(".chrysalis-agents-caret")).toContainText("▼");
    // Click to expand
    await toggle.click();
    await expect(page.locator(".chrysalis-agents-caret")).toContainText("▲");
  });

  test("chrysalis-page root element exists", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".chrysalis-page")).toBeVisible();
    // Body layout contains nodes and identity panels
    await expect(page.locator(".chrysalis-nodes")).toBeVisible();
    await expect(page.locator(".chrysalis-identity")).toBeVisible();
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

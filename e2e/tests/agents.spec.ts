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

// ── Fleet page rendering ──────────────────────────────────────

test.describe("Agent fleet page", () => {
  test("renders fleet header title and subtitle", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".fleet-header-title")).toContainText(
      "AGENT FLEET"
    );
    await expect(page.locator(".fleet-header-subtitle")).toContainText(
      "Multi-Agent Roster"
    );
  });

  test("renders + ADD AGENT button", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".fleet-add-btn")).toBeVisible();
    await expect(page.locator(".fleet-add-btn")).toContainText("ADD AGENT");
  });

  test("active badge shows correct count", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    // 2 catalog agents in mock → 2 ACTIVE
    const activeBadge = page.locator(".fleet-badge.active");
    await expect(activeBadge).toBeVisible();
    await expect(activeBadge).toContainText("2 ACTIVE");
  });

  test("total badge shows all 3 agents", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const totalBadge = page.locator(".fleet-badge.total");
    await expect(totalBadge).toBeVisible();
    await expect(totalBadge).toContainText("3 TOTAL");
  });

  test("renders 3 agent cards from list_local_agents", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".agent-card")).toHaveCount(3);
  });

  test("first agent card shows DuckDuckGo Search", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const firstCard = page.locator(".agent-card").first();
    await expect(firstCard.locator(".agent-card-name")).toContainText(
      "DuckDuckGo Search"
    );
  });

  test("agent cards show source badges", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    // Two catalog + one user_created
    await expect(page.locator(".agent-source-badge.catalog")).toHaveCount(2);
    await expect(page.locator(".agent-source-badge.user")).toHaveCount(1);
  });

  test("agent cards show truncated DID", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const firstCard = page.locator(".agent-card").first();
    const did = firstCard.locator(".agent-card-did");
    await expect(did).toBeVisible();
    // The mock DID is truncated to "did:key:z6..." format
    await expect(did).not.toBeEmpty();
  });

  test("agent cards show action type without schema: prefix", async ({
    page,
  }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    const firstCard = page.locator(".agent-card").first();
    const actionStat = firstCard.locator(".agent-stat").nth(1);
    await expect(actionStat).toContainText("SearchAction");
    // Must NOT include raw "schema:" prefix
    await expect(actionStat).not.toContainText("schema:");
  });

  test("Chrysalis sidebar panel renders", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);
    await expect(page.locator(".fleet-sidebar")).toBeVisible();
    await expect(page.locator(".fleet-panel-header")).toContainText(
      "CHRYSALIS DROP-INS"
    );
    await expect(
      page.locator("text=No remote Chrysalis nodes connected")
    ).toBeVisible();
  });
});

// ── Agent command round-trips ─────────────────────────────────

test.describe("Agent command round-trips", () => {
  test("list_local_agents returns 3 seeded agents with new fields", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    expect(agents).toHaveLength(3);

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
    expect(agents).toHaveLength(4);
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
    expect(after).toHaveLength(2);
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

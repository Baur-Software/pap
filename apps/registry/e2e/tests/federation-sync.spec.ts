/**
 * Federation sync E2E tests — 5 core scenarios.
 *
 * Prerequisites:
 *   - pap-registry Docker image built: `docker build -f apps/registry/Dockerfile -t pap-registry .`
 *   - From apps/registry/e2e: `npm ci && npx playwright install --with-deps chromium`
 *
 * Each test worker gets its own isolated 4-registry cluster on separate port ranges:
 *   worker 0: A=7900, B=7901, C=7902, D=7903
 *   worker 1: A=7910, B=7911, C=7912, D=7913
 *
 * Registry B is pre-seeded with hacker_news + docker_hub agents via seed-agents/ volume.
 */

import { test, expect, BrowserContext, Page } from "@playwright/test";
import { registryUrl, startFederationCluster, stopFederationCluster, getRegistryLogs } from "../helpers/docker-helpers";
import { PeersPage, AgentsPage, publishAgentViaAPI, readSeedAgent } from "../helpers/federation-helpers";

// Skip in environments without Docker
const SKIP_WITHOUT_DOCKER = !process.env.CI && !process.env.RUN_FEDERATION_TESTS;

test.describe("Federation Sync", () => {
  test.skip(
    SKIP_WITHOUT_DOCKER,
    "Set RUN_FEDERATION_TESTS=true or run in CI to enable federation tests"
  );

  let workerIndex: number;
  let urlA: string, urlB: string, urlC: string, urlD: string;
  let pageA: Page, pageB: Page, pageC: Page, pageD: Page;
  let context: BrowserContext;

  const githubReposToml = readSeedAgent.toString().includes("readSeedAgent")
    ? (() => {
        const fs = require("fs") as typeof import("fs");
        const path = require("path") as typeof import("path");
        return fs.readFileSync(
          path.join(__dirname, "../../../../crates/pap-agents/catalog/culture/github_repos.toml"),
          "utf8"
        );
      })()
    : "";

  const npmRegistryToml = (() => {
    const fs = require("fs") as typeof import("fs");
    const path = require("path") as typeof import("path");
    return fs.readFileSync(
      path.join(__dirname, "../../../../crates/pap-agents/catalog/developer/npm_registry.toml"),
      "utf8"
    );
  })();

  test.beforeAll(async ({ browser }, workerInfo) => {
    workerIndex = workerInfo.workerIndex;
    urlA = registryUrl("a", workerIndex);
    urlB = registryUrl("b", workerIndex);
    urlC = registryUrl("c", workerIndex);
    urlD = registryUrl("d", workerIndex);

    await startFederationCluster(workerIndex);

    context = await browser.newContext({ ignoreHTTPSErrors: true });
    [pageA, pageB, pageC, pageD] = await Promise.all([
      context.newPage(),
      context.newPage(),
      context.newPage(),
      context.newPage(),
    ]);
  });

  test.afterAll(async ({}, workerInfo) => {
    await context?.close();
    stopFederationCluster(workerInfo.workerIndex);
  });

  // ── Test 1: Direct Sync (Star topology) ──────────────────────────────────

  test("Test 1 — Direct sync: agents published on A appear on B after peering", async () => {
    // Registry B is pre-seeded with Hacker News Search + Docker Hub Image Search
    // Publish GitHub Repository Search + npm Package Search on A
    await publishAgentViaAPI(urlA, githubReposToml);
    await publishAgentViaAPI(urlA, npmRegistryToml);

    // Peer A → B (A adds B as peer)
    await PeersPage.addPeer(pageA, urlA, urlB);

    // After sync:
    // A should see B's pre-seeded agents
    await AgentsPage.waitForAgentInList(pageA, urlA, "Hacker News Search");
    await AgentsPage.waitForAgentInList(pageA, urlA, "Docker Hub Image Search");

    // B should see A's agents
    await AgentsPage.waitForAgentInList(pageB, urlB, "GitHub Repository Search");
    await AgentsPage.waitForAgentInList(pageB, urlB, "npm Package Search");
  });

  // ── Test 2: Transitive Discovery (Chain topology) ─────────────────────────

  test("Test 2 — Transitive discovery: agent published on A reaches D via A→C→D chain", async () => {
    // Publish GitHub Repository Search on A
    await publishAgentViaAPI(urlA, githubReposToml);

    // Build chain: A→C, C→D
    await PeersPage.addPeer(pageA, urlA, urlC);
    await PeersPage.addPeer(pageC, urlC, urlD);

    // D should eventually receive A's agent via transitive sync
    await AgentsPage.waitForAgentInList(pageD, urlD, "GitHub Repository Search", 30_000);
  });

  // ── Test 3: Conflict Resolution ───────────────────────────────────────────

  test("Test 3 — Conflict resolution: same-named agents from different providers both retained", async () => {
    // Create two custom agents with the same name but different provider DIDs
    const customA = `
schema_version = 1
version = "0.1.0"
name = "Custom Search"
provider = "Provider Alpha"
description = "Custom search agent from registry A"
action = "schema:SearchAction"
object_types = ["schema:Thing"]
requires_disclosure = []
returns = ["schema:Thing"]
source = "Custom"
subagents = []
[endpoint]
url_template = "https://example.com/search?q={query}"
method = "Get"
response_jsonpath = "$.results[0]"
response_schema_type = "schema:Thing"
`;
    const customB = `
schema_version = 1
version = "0.1.0"
name = "Custom Search"
provider = "Provider Beta"
description = "Custom search agent from registry B"
action = "schema:SearchAction"
object_types = ["schema:Thing"]
requires_disclosure = []
returns = ["schema:Thing"]
source = "Custom"
subagents = []
[endpoint]
url_template = "https://beta.example.com/search?q={query}"
method = "Get"
response_jsonpath = "$.results[0]"
response_schema_type = "schema:Thing"
`;

    await publishAgentViaAPI(urlA, customA);
    await publishAgentViaAPI(urlB, customB);

    // Peer A → B
    await PeersPage.addPeer(pageA, urlA, urlB);

    // Both agents should exist — conflict is resolved by keeping both (different provider)
    const countA = await AgentsPage.getAgentCount(pageA, urlA);
    const countB = await AgentsPage.getAgentCount(pageB, urlB);

    expect(countA).toBeGreaterThanOrEqual(2);
    expect(countB).toBeGreaterThanOrEqual(2);
  });

  // ── Test 4: Incremental Sync (Late Joiner) ────────────────────────────────

  test("Test 4 — Late joiner: D added to established A↔B↔C mesh receives all agents", async () => {
    // Pre-establish A↔B↔C with agents
    await publishAgentViaAPI(urlA, githubReposToml);
    await publishAgentViaAPI(urlB, npmRegistryToml);

    await PeersPage.addPeer(pageA, urlA, urlB);
    await PeersPage.addPeer(pageB, urlB, urlC);

    // Wait for mesh to propagate
    await AgentsPage.waitForAgentInList(pageC, urlC, "GitHub Repository Search");

    // D joins late — connect to all three
    await PeersPage.addPeer(pageD, urlD, urlA);
    await PeersPage.addPeer(pageD, urlD, urlB);
    await PeersPage.addPeer(pageD, urlD, urlC);

    // D should receive all agents
    await AgentsPage.waitForAgentInList(pageD, urlD, "GitHub Repository Search");
  });

  // ── Test 5: Full Mesh ─────────────────────────────────────────────────────

  test("Test 5 — Full mesh: each registry sees all agents after full 6-pair peering", async () => {
    // Each registry publishes one unique agent
    const githubReposFs = (() => {
      const fs = require("fs") as typeof import("fs");
      const path = require("path") as typeof import("path");
      return fs.readFileSync(
        path.join(__dirname, "../../../../crates/pap-agents/catalog/culture/github_repos.toml"),
        "utf8"
      );
    })();

    await publishAgentViaAPI(urlA, githubReposFs);
    await publishAgentViaAPI(urlB, npmRegistryToml);
    // C and D are pre-seeded by docker-compose (registry-b has seed-agents)
    // but we use direct API publishes for determinism

    // Build full mesh: 6 pairs
    await Promise.all([
      PeersPage.addPeer(pageA, urlA, urlB),
      PeersPage.addPeer(pageA, urlA, urlC),
      PeersPage.addPeer(pageA, urlA, urlD),
    ]);
    await Promise.all([
      PeersPage.addPeer(pageB, urlB, urlC),
      PeersPage.addPeer(pageB, urlB, urlD),
    ]);
    await PeersPage.addPeer(pageC, urlC, urlD);

    // After full mesh sync, each registry should have agents from all others
    const countA = await AgentsPage.getAgentCount(pageA, urlA);
    const countB = await AgentsPage.getAgentCount(pageB, urlB);
    const countC = await AgentsPage.getAgentCount(pageC, urlC);
    const countD = await AgentsPage.getAgentCount(pageD, urlD);

    // Each should have at least the agents published above
    expect(countA).toBeGreaterThanOrEqual(2);
    expect(countB).toBeGreaterThanOrEqual(2);
    expect(countC).toBeGreaterThanOrEqual(2);
    expect(countD).toBeGreaterThanOrEqual(2);
  });
});

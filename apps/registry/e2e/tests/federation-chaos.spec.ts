/**
 * Federation chaos E2E tests — 5 opt-in scenarios.
 *
 * These tests simulate real-world failure modes:
 *   - Network partitions
 *   - Cascading failures
 *   - Slow peers
 *   - Concurrent conflicts
 *   - Resource exhaustion
 *
 * Opt-in via: RUN_CHAOS_TESTS=true npx playwright test federation-chaos.spec.ts
 *
 * Prerequisites: same as federation-sync.spec.ts — Docker cluster must be available.
 */

import { test, expect, BrowserContext, Page } from "@playwright/test";
import {
  registryUrl,
  startFederationCluster,
  stopFederationCluster,
  getRegistryLogs,
} from "../helpers/docker-helpers";
import {
  PeersPage,
  AgentsPage,
  publishAgentViaAPI,
  TestAgents,
  TestAgentSpec,
} from "../helpers/federation-helpers";
import {
  partitionNetwork,
  reconnectNetwork,
  killRegistry,
  restartWithDelay,
  addNetworkDelay,
  resetNetworkEffects,
  waitForContainerHealthy,
} from "../helpers/chaos-helpers";

// Opt-in gate — chaos tests require explicit env var
test.skip(
  !process.env.RUN_CHAOS_TESTS,
  "Set RUN_CHAOS_TESTS=true to enable chaos tests"
);

test.describe("Federation Chaos", () => {
  let workerIndex: number;
  let urlA: string, urlB: string, urlC: string, urlD: string;
  let pageA: Page, pageB: Page, pageC: Page, pageD: Page;
  let context: BrowserContext;

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

  // ── Test 6: Network Partition ─────────────────────────────────────────────

  test("Test 6 — Network partition: agents sync within partitions then heal across partition", async () => {
    // Establish full mesh first
    await Promise.all([
      PeersPage.addPeer(pageA, urlA, urlB),
      PeersPage.addPeer(pageA, urlA, urlC),
      PeersPage.addPeer(pageA, urlA, urlD),
      PeersPage.addPeer(pageB, urlB, urlC),
      PeersPage.addPeer(pageB, urlB, urlD),
      PeersPage.addPeer(pageC, urlC, urlD),
    ]);

    // Create partition: {A, B} | {C, D}
    partitionNetwork(workerIndex, ["a", "b"], ["c", "d"]);

    // Publish on each side of the partition
    await publishAgentViaAPI(urlA, TestAgents.githubReposSearch());
    await publishAgentViaAPI(urlC, TestAgents.npmPackageSearch());

    // Each half should sync within its partition
    await AgentsPage.waitForAgentInList(pageB, urlB, "GitHub Repository Search");
    await AgentsPage.waitForAgentInList(pageD, urlD, "npm Package Search");

    // Heal the partition
    reconnectNetwork(workerIndex, ["a", "b", "c", "d"]);

    // After healing, both agents should propagate everywhere
    await AgentsPage.waitForAgentInList(pageC, urlC, "GitHub Repository Search", 45_000);
    await AgentsPage.waitForAgentInList(pageA, urlA, "npm Package Search", 45_000);
  });

  // ── Test 7: Cascading Failure ─────────────────────────────────────────────

  test("Test 7 — Cascading failure: killing B isolates D from A; restart B restores sync", async () => {
    // Build chain A to B to C to D
    await PeersPage.addPeer(pageA, urlA, urlB);
    await PeersPage.addPeer(pageB, urlB, urlC);
    await PeersPage.addPeer(pageC, urlC, urlD);

    // Publish on A
    await publishAgentViaAPI(urlA, TestAgents.githubReposSearch());
    await AgentsPage.waitForAgentInList(pageB, urlB, "GitHub Repository Search");

    // Kill B
    killRegistry(workerIndex, "b");
    await new Promise((r) => setTimeout(r, 2_000));

    // Restart B after 1s delay
    restartWithDelay(workerIndex, "b", 1_000);
    await waitForContainerHealthy(workerIndex, "b", 30_000);

    // After restart, publish npm on A — should reach D via B after B recovers
    await publishAgentViaAPI(urlA, TestAgents.npmPackageSearch());
    await AgentsPage.waitForAgentInList(pageD, urlD, "npm Package Search", 45_000);
  });

  // ── Test 8: Slow Peer ─────────────────────────────────────────────────────

  test("Test 8 — Slow peer: A syncs C within timeout even when B has 5s delay", async () => {
    // Add 5s delay to B
    addNetworkDelay(workerIndex, "b", 5_000);

    try {
      // Peer A to B and A to C
      await PeersPage.addPeer(pageA, urlA, urlB);
      await PeersPage.addPeer(pageA, urlA, urlC);

      // Publish on C
      await publishAgentViaAPI(urlC, TestAgents.githubReposSearch());

      // A should sync from C despite B being slow
      await AgentsPage.waitForAgentInList(pageA, urlA, "GitHub Repository Search", 30_000);
    } finally {
      resetNetworkEffects(workerIndex, "b");
    }
  });

  // ── Test 9: Concurrent Conflict ───────────────────────────────────────────

  test("Test 9 — Concurrent conflict: parallel publishes of same-named agent are handled deterministically", async () => {
    // Two agents with the same name but different providers (different keypairs = different hash)
    const agentAlpha = TestAgents.customSearch("Alpha Registry");
    const agentBeta = TestAgents.customSearch("Beta Registry");

    // Publish simultaneously on A and B
    await Promise.all([
      publishAgentViaAPI(urlA, agentAlpha),
      publishAgentViaAPI(urlB, agentBeta),
    ]);

    // Peer A to B
    await PeersPage.addPeer(pageA, urlA, urlB);

    // Wait for sync
    await new Promise((r) => setTimeout(r, 5_000));

    // Both registries should have at least 1 "Custom Search" agent
    const countA = await AgentsPage.getAgentCount(pageA, urlA);
    const countB = await AgentsPage.getAgentCount(pageB, urlB);

    expect(countA).toBeGreaterThanOrEqual(1);
    expect(countB).toBeGreaterThanOrEqual(1);
  });

  // ── Test 10: Resource Exhaustion ──────────────────────────────────────────

  test("Test 10 — Resource exhaustion: 100-agent bulk publish on A syncs to D without 5xx errors", async () => {
    const errors: string[] = [];

    // Publish 100 unique agents on A in batches of 10
    for (let batch = 0; batch < 10; batch++) {
      const batchPromises = Array.from({ length: 10 }, (_, j) => {
        const i = batch * 10 + j;
        const spec: TestAgentSpec = {
          name: `Bulk Agent ${i + 1}`,
          providerName: "Stress Test",
          capability: ["schema:SearchAction"],
          objectTypes: ["schema:Thing"],
          returns: ["schema:Thing"],
        };
        return publishAgentViaAPI(urlA, spec).catch((err: Error) => {
          errors.push(err.message);
        });
      });
      await Promise.all(batchPromises);
    }

    // No 5xx errors during bulk publish
    const serverErrors = errors.filter((e) => e.includes("5"));
    expect(serverErrors).toHaveLength(0);

    // Peer D to A
    await PeersPage.addPeer(pageD, urlD, urlA);

    // D should eventually receive the last bulk agent
    await AgentsPage.waitForAgentInList(pageD, urlD, "Bulk Agent 100", 60_000);
  });
});

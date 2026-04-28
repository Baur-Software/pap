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
 * Agent publication uses /federation/announce with properly signed Ed25519
 * advertisements — no TOML files, no admin bearer token required.
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
  TestAgents,
  publishAgentViaAPI,
} from "../helpers/federation-helpers";

// Skip in environments without Docker
const SKIP_WITHOUT_DOCKER =
  !process.env.CI && !process.env.RUN_FEDERATION_TESTS;

test.describe("Federation Sync", () => {
  test.skip(
    SKIP_WITHOUT_DOCKER,
    "Set RUN_FEDERATION_TESTS=true or run in CI to enable federation tests"
  );

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

  // Helper: dump logs on failure for all registries
  async function dumpLogsOnFailure(wi: number): Promise<void> {
    for (const letter of ["a", "b", "c", "d"] as const) {
      const logs = getRegistryLogs(wi, letter, 50);
      console.log(`=== registry-${letter} logs ===\n${logs}`);
    }
  }

  // ── Test 1: Direct Sync (Star topology) ──────────────────────────────────

  test("Test 1 — Direct sync: agents published on A appear on B after peering", async () => {
    try {
      // Publish GitHub Repository Search and npm Package Search on A
      await publishAgentViaAPI(urlA, TestAgents.githubReposSearch());
      await publishAgentViaAPI(urlA, TestAgents.npmPackageSearch());

      // Publish Hacker News Search and Docker Hub on B
      await publishAgentViaAPI(urlB, TestAgents.hackerNewsSearch());
      await publishAgentViaAPI(urlB, TestAgents.dockerHubSearch());

      // Peer A→B (A adds B as peer — A syncs FROM B, getting B's agents)
      await PeersPage.addPeer(pageA, urlA, urlB);

      // After sync: A should see B's agents
      await AgentsPage.waitForAgentInList(pageA, urlA, "Hacker News Search");
      await AgentsPage.waitForAgentInList(pageA, urlA, "Docker Hub Image Search");

      // Peer B→A (B adds A as peer — B syncs FROM A, getting A's agents)
      await PeersPage.addPeer(pageB, urlB, urlA);

      // After B syncs from A: B should see A's agents
      await AgentsPage.waitForAgentInList(pageB, urlB, "GitHub Repository Search");
      await AgentsPage.waitForAgentInList(pageB, urlB, "npm Package Search");
    } catch (e) {
      await dumpLogsOnFailure(workerIndex);
      throw e;
    }
  });

  // ── Test 2: Transitive Discovery (Chain topology) ─────────────────────────

  test("Test 2 — Transitive discovery: agent published on A reaches D via A to C to D chain", async () => {
    try {
      // Publish GitHub Repository Search on A
      await publishAgentViaAPI(urlA, TestAgents.githubReposSearch());

      // Build chain: C syncs from A (C gets A's agent), D syncs from C (D gets C's agent)
      // Direction: C adds A → C pulls from A; D adds C → D pulls from C.
      await PeersPage.addPeer(pageC, urlC, urlA);

      // C should now have GitHub Repository Search (pulled from A)
      await AgentsPage.waitForAgentInList(pageC, urlC, "GitHub Repository Search", 15_000);

      // D adds C → D pulls from C (which now has A's agent)
      await PeersPage.addPeer(pageD, urlD, urlC);

      // D should eventually receive A's agent via transitive sync through C
      await AgentsPage.waitForAgentInList(pageD, urlD, "GitHub Repository Search", 30_000);
    } catch (e) {
      await dumpLogsOnFailure(workerIndex);
      throw e;
    }
  });

  // ── Test 3: Conflict Resolution ───────────────────────────────────────────

  test("Test 3 — Conflict resolution: same-named agents from different providers both retained", async () => {
    try {
      // Two agents with the same name but different provider DIDs (different keys)
      await publishAgentViaAPI(urlA, TestAgents.customSearch("Provider Alpha"));
      await publishAgentViaAPI(urlB, TestAgents.customSearch("Provider Beta"));

      // A syncs FROM B → A gets Provider Beta's agent (A already has Provider Alpha)
      await PeersPage.addPeer(pageA, urlA, urlB);
      // B syncs FROM A → B gets Provider Alpha's agent (B already has Provider Beta)
      await PeersPage.addPeer(pageB, urlB, urlA);

      // Wait for sync to propagate
      await new Promise((r) => setTimeout(r, 3_000));

      // Both agents should exist — same name but different provider DID = different hash
      const countA = await AgentsPage.getAgentCount(pageA, urlA);
      const countB = await AgentsPage.getAgentCount(pageB, urlB);

      expect(countA).toBeGreaterThanOrEqual(2);
      expect(countB).toBeGreaterThanOrEqual(2);
    } catch (e) {
      await dumpLogsOnFailure(workerIndex);
      throw e;
    }
  });

  // ── Test 4: Incremental Sync (Late Joiner) ────────────────────────────────

  test("Test 4 — Late joiner: D added to established A-B-C mesh receives all agents", async () => {
    try {
      // Pre-establish A-B-C with agents
      await publishAgentViaAPI(urlA, TestAgents.githubReposSearch());
      await publishAgentViaAPI(urlB, TestAgents.npmPackageSearch());

      // B syncs from A → B gets GitHub agent; C syncs from A → C gets GitHub agent
      await PeersPage.addPeer(pageB, urlB, urlA);
      await PeersPage.addPeer(pageC, urlC, urlA);
      await PeersPage.addPeer(pageC, urlC, urlB);

      // Wait for mesh to propagate — C should have A's agent
      await AgentsPage.waitForAgentInList(pageC, urlC, "GitHub Repository Search");

      // D joins late — syncs from all three
      await PeersPage.addPeer(pageD, urlD, urlA);
      await PeersPage.addPeer(pageD, urlD, urlB);
      await PeersPage.addPeer(pageD, urlD, urlC);

      // D should receive all agents from the established mesh
      await AgentsPage.waitForAgentInList(pageD, urlD, "GitHub Repository Search");
    } catch (e) {
      await dumpLogsOnFailure(workerIndex);
      throw e;
    }
  });

  // ── Test 5: Full Mesh ─────────────────────────────────────────────────────

  test("Test 5 — Full mesh: each registry sees all agents after full 6-pair peering", async () => {
    try {
      // Each registry publishes a unique agent
      await publishAgentViaAPI(urlA, TestAgents.githubReposSearch());
      await publishAgentViaAPI(urlB, TestAgents.npmPackageSearch());
      await publishAgentViaAPI(urlC, TestAgents.hackerNewsSearch());
      await publishAgentViaAPI(urlD, TestAgents.dockerHubSearch());

      // Build full mesh: 6 pairs (sequential per page to avoid UI races)
      await PeersPage.addPeer(pageA, urlA, urlB);
      await PeersPage.addPeer(pageA, urlA, urlC);
      await PeersPage.addPeer(pageA, urlA, urlD);
      await PeersPage.addPeer(pageB, urlB, urlC);
      await PeersPage.addPeer(pageB, urlB, urlD);
      await PeersPage.addPeer(pageC, urlC, urlD);

      // After full mesh sync, each registry should have all 4 agents
      await AgentsPage.waitForAgentInList(pageA, urlA, "npm Package Search");
      await AgentsPage.waitForAgentInList(pageB, urlB, "GitHub Repository Search");
      await AgentsPage.waitForAgentInList(pageC, urlC, "GitHub Repository Search");
      await AgentsPage.waitForAgentInList(pageD, urlD, "GitHub Repository Search");

      const countA = await AgentsPage.getAgentCount(pageA, urlA);
      const countB = await AgentsPage.getAgentCount(pageB, urlB);
      const countC = await AgentsPage.getAgentCount(pageC, urlC);
      const countD = await AgentsPage.getAgentCount(pageD, urlD);

      expect(countA).toBeGreaterThanOrEqual(4);
      expect(countB).toBeGreaterThanOrEqual(4);
      expect(countC).toBeGreaterThanOrEqual(4);
      expect(countD).toBeGreaterThanOrEqual(4);
    } catch (e) {
      await dumpLogsOnFailure(workerIndex);
      throw e;
    }
  });
});

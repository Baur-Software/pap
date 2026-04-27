/**
 * Page object helpers for federation E2E tests.
 *
 * Selector sources:
 *   apps/registry/src/ui/pages/peers.rs
 *   apps/registry/src/ui/pages/agents.rs
 *   apps/registry/src/ui/pages/dashboard.rs
 *   apps/registry/src/ui/pages/agent_designer.rs
 */

import { Page, expect } from "@playwright/test";

// ─────────────────────────────────────────────────────────────────────────────
// PeersPage
// ─────────────────────────────────────────────────────────────────────────────

export const PeersPage = {
  /** Navigate to the Peers page on a registry. */
  async navigate(page: Page, baseUrl: string): Promise<void> {
    await page.goto(`${baseUrl}/peers`, { waitUntil: "networkidle" });
  },

  /**
   * Add a peer via the UI.
   * Clicks ".btn.btn-primary" (Add Peer), fills the endpoint input,
   * submits, and waits for ".success-banner".
   */
  async addPeer(
    page: Page,
    baseUrl: string,
    endpoint: string,
    trustMode = "tofu"
  ): Promise<void> {
    await this.navigate(page, baseUrl);

    // Open the add peer modal
    await page.locator(".btn.btn-primary").first().click();
    await expect(page.locator(".modal")).toBeVisible();

    // Fill endpoint
    await page.locator(".form-input[name=endpoint], .form-input").first().fill(endpoint);

    // Set trust mode if a selector exists
    const trustSelect = page.locator("select[name=trust_mode], select.trust-mode");
    if ((await trustSelect.count()) > 0) {
      await trustSelect.selectOption(trustMode);
    }

    // Submit
    await page.locator(".modal-actions .btn.btn-primary").click();

    // Wait for success
    await expect(page.locator(".success-banner")).toBeVisible({ timeout: 10_000 });
  },

  /** Returns an array of { endpoint, status } for all visible peers. */
  async listPeers(page: Page): Promise<{ endpoint: string; status: string }[]> {
    const rows = await page.locator(".peer-row").all();
    return Promise.all(
      rows.map(async (row) => {
        const endpoint = (await row.locator(".peer-endpoint").textContent()) ?? "";
        const statusClass =
          (await row.locator(".peer-indicator").getAttribute("class")) ?? "";
        const status = statusClass.includes("online")
          ? "online"
          : statusClass.includes("offline")
          ? "offline"
          : "unknown";
        return { endpoint: endpoint.trim(), status };
      })
    );
  },

  /** Trigger sync for a specific peer endpoint. */
  async triggerSync(page: Page, endpoint: string): Promise<void> {
    const row = page.locator(".peer-row").filter({ hasText: endpoint });
    await row.locator(".btn.btn-secondary.btn-sm").click();
  },

  /** Get the status indicator class for a specific peer. */
  async getPeerStatus(page: Page, endpoint: string): Promise<string> {
    const row = page.locator(".peer-row").filter({ hasText: endpoint });
    return (await row.locator(".peer-indicator").getAttribute("class")) ?? "";
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// AgentsPage
// ─────────────────────────────────────────────────────────────────────────────

export const AgentsPage = {
  /** Navigate to the Agents page on a registry. */
  async navigate(page: Page, baseUrl: string): Promise<void> {
    await page.goto(`${baseUrl}/agents`, { waitUntil: "networkidle" });
  },

  /**
   * Poll until an agent with the given name appears in the list.
   * Uses exponential backoff: 100ms → 200ms → 500ms → 1s → 2s → 5s.
   */
  async waitForAgentInList(
    page: Page,
    baseUrl: string,
    agentName: string,
    timeoutMs = 30_000
  ): Promise<void> {
    const start = Date.now();
    const delays = [100, 200, 500, 1000, 2000, 5000];
    let attempt = 0;

    while (Date.now() - start < timeoutMs) {
      await page.goto(`${baseUrl}/agents`, { waitUntil: "networkidle" });

      const found = await page
        .locator(".agent-row, tr, li")
        .filter({ hasText: agentName })
        .count();
      if (found > 0) return;

      // Also check page text as a fallback
      const content = await page.content();
      if (content.includes(agentName)) return;

      const delay = delays[Math.min(attempt, delays.length - 1)];
      await new Promise((r) => setTimeout(r, delay));
      attempt++;
    }

    throw new Error(
      `Agent "${agentName}" did not appear at ${baseUrl}/agents within ${timeoutMs}ms`
    );
  },

  /** Get the agent count from the dashboard stat card. */
  async getAgentCount(page: Page, baseUrl: string): Promise<number> {
    await page.goto(`${baseUrl}`, { waitUntil: "networkidle" });
    const tealStat = page.locator(".stat-value.teal");
    if ((await tealStat.count()) > 0) {
      const text = await tealStat.first().textContent();
      return parseInt(text?.trim() ?? "0", 10);
    }
    // Fallback: count rows on agents page
    await page.goto(`${baseUrl}/agents`, { waitUntil: "networkidle" });
    return page.locator(".agent-row, .agent-list-item").count();
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// AgentDesignerPage
// ─────────────────────────────────────────────────────────────────────────────

export const AgentDesignerPage = {
  /** Navigate to /agents/new. */
  async navigate(page: Page, baseUrl: string): Promise<void> {
    await page.goto(`${baseUrl}/agents/new`, { waitUntil: "networkidle" });
  },

  /** Fill required form fields for a new agent. */
  async fillForm(
    page: Page,
    data: {
      name: string;
      provider_name?: string;
      capabilities?: string;
    }
  ): Promise<void> {
    await page.locator('[name=name]').fill(data.name);
    if (data.provider_name) {
      await page.locator('[name=provider_name]').fill(data.provider_name);
    }
    if (data.capabilities) {
      await page.locator('[name=capabilities]').fill(data.capabilities);
    }
  },

  /** Submit the agent designer form. */
  async publish(page: Page): Promise<void> {
    await page.locator('button[type=submit], .btn.btn-primary').last().click();
    // Wait for success or redirect
    await Promise.race([
      page.waitForURL((url) => !url.pathname.includes("/new"), { timeout: 10_000 }),
      expect(page.locator(".success-banner")).toBeVisible({ timeout: 10_000 }),
    ]);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// API helpers (bypasses UI for seeding)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Publish an agent via the registry's admin API (TOML body).
 * Uses the /admin/agents endpoint expected to exist on the registry.
 */
export async function publishAgentViaAPI(
  baseUrl: string,
  agentToml: string
): Promise<void> {
  const res = await fetch(`${baseUrl}/admin/agents`, {
    method: "POST",
    body: agentToml,
    headers: { "Content-Type": "application/toml" },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(
      `publishAgentViaAPI failed: ${res.status} ${res.statusText}\n${body}`
    );
  }
}

/** Read the content of a seed agent TOML file. */
export function readSeedAgent(filename: string): string {
  const fs = require("fs") as typeof import("fs");
  const p = require("path") as typeof import("path");
  // Reject any filename containing path separators or traversal sequences
  // to prevent path traversal (Semgrep path-join-resolve-traversal).
  if (/[/\\]|\.\./.test(filename)) {
    throw new Error(`readSeedAgent: invalid filename '${filename}'`);
  }
  const seedDir = p.resolve(__dirname, "..", "seed-agents");
  const fullPath = p.resolve(seedDir, filename);
  // Verify resolved path stays within the seed-agents directory
  if (!fullPath.startsWith(seedDir + p.sep) && fullPath !== seedDir) {
    throw new Error(`readSeedAgent: path traversal detected for '${filename}'`);
  }
  return fs.readFileSync(fullPath, "utf8");
}

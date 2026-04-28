/**
 * Page object helpers for federation E2E tests.
 *
 * Selector sources:
 *   apps/registry/src/ui/pages/peers.rs
 *   apps/registry/src/ui/pages/agents.rs
 *   apps/registry/src/ui/pages/dashboard.rs
 *   apps/registry/src/ui/pages/agent_designer.rs
 *
 * Agent publication uses the /federation/announce endpoint with properly
 * signed AgentAdvertisement JSON (Ed25519, did:key format) — no TOML, no
 * admin bearer token required.
 */

import { Page, expect } from "@playwright/test";
import * as crypto from "crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Agent advertisement signing utilities
// ─────────────────────────────────────────────────────────────────────────────

/** Base58btc encode (Bitcoin alphabet). */
function base58Encode(bytes: Uint8Array): string {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * BigInt(256) + BigInt(byte);
  }
  let encoded = "";
  while (num > BigInt(0)) {
    encoded = ALPHABET[Number(num % BigInt(58))] + encoded;
    num = num / BigInt(58);
  }
  // Leading 0-bytes map to '1'
  for (const byte of bytes) {
    if (byte === 0) {
      encoded = "1" + encoded;
    } else {
      break;
    }
  }
  return encoded;
}

/**
 * Derive a did:key identifier from an Ed25519 public key (32 bytes).
 * Format: did:key:z<base58btc([0xed, 0x01] ++ pubkey_bytes)>
 * Matches pap-did::public_key_to_did() in Rust.
 */
function publicKeyToDid(pubKeyBytes: Uint8Array): string {
  const prefixed = new Uint8Array(2 + pubKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pubKeyBytes, 2);
  return "did:key:z" + base58Encode(prefixed);
}

/** URL-safe base64 without padding (matches base64::URL_SAFE_NO_PAD in Rust). */
function base64urlNoPad(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Build canonical JSON bytes for signing.
 * Mirrors canonical_bytes() in crates/pap-marketplace/src/advertisement.rs.
 * Only identity/capability fields — signature, metrics, configurable_properties excluded.
 */
function canonicalBytes(ad: Record<string, unknown>): Buffer {
  const canonical = {
    "@context": ad["@context"],
    "@type": ad["@type"],
    name: ad.name,
    version: ad.version,
    provider: ad.provider,
    capability: ad.capability,
    object_types: ad.object_types,
    requires_disclosure: ad.requires_disclosure,
    returns: ad.returns,
    ttl_min: ad.ttl_min,
    signed_by: ad.signed_by,
  };
  return Buffer.from(JSON.stringify(canonical));
}

/** Spec for creating a test agent advertisement. */
export interface TestAgentSpec {
  name: string;
  providerName?: string;
  capability?: string[];
  objectTypes?: string[];
  requiresDisclosure?: string[];
  returns?: string[];
  ttlMin?: number;
}

/**
 * Create a signed AgentAdvertisement JSON object.
 * Generates a fresh Ed25519 key pair for each call, matching the Rust signing logic.
 */
export function createSignedAdvertisement(spec: TestAgentSpec): Record<string, unknown> {
  // Generate fresh Ed25519 key pair
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

  // Extract raw 32-byte public key from DER-encoded SubjectPublicKeyInfo
  const pubKeyDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const pubKeyBytes = new Uint8Array(pubKeyDer.slice(-32));

  // Derive DID
  const did = publicKeyToDid(pubKeyBytes);

  // Build unsigned advertisement
  const ad: Record<string, unknown> = {
    "@context": "https://schema.org",
    "@type": "schema:Service",
    name: spec.name,
    version: "0.1.0",
    provider: {
      "@type": "schema:Organization",
      name: spec.providerName ?? "E2E Test Provider",
      did,
    },
    capability: spec.capability ?? ["schema:SearchAction"],
    object_types: spec.objectTypes ?? ["schema:Thing"],
    requires_disclosure: spec.requiresDisclosure ?? [],
    returns: spec.returns ?? ["schema:Thing"],
    ttl_min: spec.ttlMin ?? 300,
    signed_by: did,
    // algorithm serializes as "EdDSA" (matches #[serde(rename = "EdDSA")] in Rust)
    algorithm: "EdDSA",
    signature: null,
  };

  // Sign the canonical bytes
  const msgBytes = canonicalBytes(ad);
  const sigBuffer = crypto.sign(null, msgBytes, privateKey) as Buffer;
  ad.signature = base64urlNoPad(new Uint8Array(sigBuffer));

  return ad;
}

/**
 * Publish an agent to a registry via the federation announce protocol.
 *
 * Creates a fresh Ed25519 keypair, builds a signed AgentAdvertisement,
 * and POSTs to /federation/announce as FederationMessage::Announce.
 * No bearer token required; the registry accepts federation announcements
 * from any peer with a valid Ed25519 signature.
 */
export async function publishAgentViaAPI(
  baseUrl: string,
  agentSpec: TestAgentSpec
): Promise<void> {
  const advertisement = createSignedAdvertisement(agentSpec);

  // FederationMessage uses #[serde(tag = "type")], so variant name is in "type" field
  const body = JSON.stringify({ type: "Announce", advertisement });

  const res = await fetch(`${baseUrl}/federation/announce`, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/json" },
  });

  if (!res.ok) {
    const responseBody = await res.text().catch(() => "");
    throw new Error(
      `publishAgentViaAPI failed: ${res.status} ${res.statusText}\n${responseBody}`
    );
  }

  const ack = (await res.json()) as Record<string, unknown>;
  if (ack["type"] === "AnnounceAck" && ack["accepted"] === false) {
    throw new Error(
      `publishAgentViaAPI: registry rejected advertisement (hash: ${String(ack["hash"])}). ` +
        "Signature verification failed."
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-defined test agent specs
// ─────────────────────────────────────────────────────────────────────────────

/** Named test agent specs matching the catalog agents used in test scenarios. */
export const TestAgents = {
  hackerNewsSearch: (): TestAgentSpec => ({
    name: "Hacker News Search",
    providerName: "Algolia / Y Combinator",
    capability: ["schema:SearchAction"],
    objectTypes: ["schema:DiscussionForumPosting"],
    returns: ["schema:DiscussionForumPosting"],
  }),

  dockerHubSearch: (): TestAgentSpec => ({
    name: "Docker Hub Image Search",
    providerName: "Docker Inc.",
    capability: ["schema:SearchAction"],
    objectTypes: ["schema:SoftwareApplication"],
    returns: ["schema:SoftwareApplication"],
  }),

  githubReposSearch: (): TestAgentSpec => ({
    name: "GitHub Repository Search",
    providerName: "GitHub Inc.",
    capability: ["schema:SearchAction"],
    objectTypes: ["schema:SoftwareSourceCode"],
    returns: ["schema:SoftwareSourceCode"],
  }),

  npmPackageSearch: (): TestAgentSpec => ({
    name: "npm Package Search",
    providerName: "npm Inc.",
    capability: ["schema:SearchAction"],
    objectTypes: ["schema:SoftwareApplication"],
    returns: ["schema:SoftwareApplication"],
  }),

  customSearch: (providerName: string): TestAgentSpec => ({
    name: "Custom Search",
    providerName,
    capability: ["schema:SearchAction"],
    objectTypes: ["schema:Thing"],
    returns: ["schema:Thing"],
  }),
};

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
   * Uses exponential backoff: 100ms to 200ms to 500ms to 1s to 2s to 5s.
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
    await page.locator("[name=name]").fill(data.name);
    if (data.provider_name) {
      await page.locator("[name=provider_name]").fill(data.provider_name);
    }
    if (data.capabilities) {
      await page.locator("[name=capabilities]").fill(data.capabilities);
    }
  },

  /** Submit the agent designer form. */
  async publish(page: Page): Promise<void> {
    await page.locator("button[type=submit], .btn.btn-primary").last().click();
    // Wait for success or redirect
    await Promise.race([
      page.waitForURL((url) => !url.pathname.includes("/new"), { timeout: 10_000 }),
      expect(page.locator(".success-banner")).toBeVisible({ timeout: 10_000 }),
    ]);
  },
};

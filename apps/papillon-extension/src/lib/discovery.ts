/**
 * PAP manifest discovery — same-origin probe and validation.
 *
 * Fetches /.well-known/pap-manifest from a given origin and validates
 * the response structure. Used by the content script (same-origin) and
 * the service worker (context menu upgrade).
 */

// ── Types ─────────────────────────────────────────────────────────────

/** Shape of /.well-known/pap-manifest as served by PAP agents. */
export interface PapManifest {
  agent_id: string;
  name: string;
  version?: string;
  public_key?: string;
  tools?: PapTool[];
  categories?: string[];
}

export interface PapTool {
  name: string;
  description?: string;
  endpoint?: string;
  method?: string;
}

// ── Validation ────────────────────────────────────────────────────────

/**
 * Type-check a parsed JSON response as a PapManifest.
 * Must have `agent_id` (string) and `name` (string) at minimum.
 */
export function validateManifest(data: unknown): PapManifest | null {
  if (
    typeof data !== "object" ||
    data === null ||
    Array.isArray(data)
  ) {
    return null;
  }

  const obj = data as Record<string, unknown>;

  if (typeof obj.agent_id !== "string" || obj.agent_id.length === 0) {
    return null;
  }
  if (typeof obj.name !== "string" || obj.name.length === 0) {
    return null;
  }

  const manifest: PapManifest = {
    agent_id: obj.agent_id,
    name: obj.name,
  };

  if (typeof obj.version === "string") manifest.version = obj.version;
  if (typeof obj.public_key === "string") manifest.public_key = obj.public_key;
  if (Array.isArray(obj.categories)) {
    manifest.categories = obj.categories.filter(
      (c: unknown) => typeof c === "string"
    );
  }
  if (Array.isArray(obj.tools)) {
    manifest.tools = obj.tools
      .filter(
        (t: unknown) =>
          typeof t === "object" &&
          t !== null &&
          typeof (t as Record<string, unknown>).name === "string"
      )
      .map((t: unknown) => {
        const tool = t as Record<string, unknown>;
        const result: PapTool = { name: tool.name as string };
        if (typeof tool.description === "string")
          result.description = tool.description;
        if (typeof tool.endpoint === "string")
          result.endpoint = tool.endpoint;
        if (typeof tool.method === "string") result.method = tool.method;
        return result;
      });
  }

  return manifest;
}

// ── Fetch ─────────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 5_000;

/**
 * Fetch /.well-known/pap-manifest from a URL.
 *
 * Accepts a full URL (for link-rel discovery) or an origin
 * (appends the well-known path automatically).
 *
 * Returns a validated PapManifest or null on any failure.
 * Never throws.
 */
export async function fetchManifest(
  urlOrOrigin: string
): Promise<PapManifest | null> {
  try {
    const url = urlOrOrigin.includes("/.well-known/")
      ? urlOrOrigin
      : `${urlOrOrigin}/.well-known/pap-manifest`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
      // Prevent credentials from leaking to the manifest endpoint
      credentials: "omit",
    });

    clearTimeout(timer);

    if (!resp.ok) return null;

    const data: unknown = await resp.json();
    return validateManifest(data);
  } catch {
    return null;
  }
}

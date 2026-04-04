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
 * Bounds: agent_id and name each max 1000 chars, tools array max 500 items.
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

  if (typeof obj.agent_id !== "string" || obj.agent_id.length === 0 || obj.agent_id.length > 1000) {
    return null;
  }
  if (typeof obj.name !== "string" || obj.name.length === 0 || obj.name.length > 1000) {
    return null;
  }

  const manifest: PapManifest = {
    agent_id: obj.agent_id,
    name: obj.name,
  };

  if (typeof obj.version === "string" && obj.version.length <= 100) manifest.version = obj.version;
  if (typeof obj.public_key === "string" && obj.public_key.length <= 5000) manifest.public_key = obj.public_key;
  if (Array.isArray(obj.categories)) {
    manifest.categories = obj.categories
      .slice(0, 100) // Max 100 categories
      .filter((c: unknown) => typeof c === "string" && c.length <= 200)
      .map((c: unknown) => (c as string));
  }
  if (Array.isArray(obj.tools)) {
    manifest.tools = (obj.tools as unknown[])
      .slice(0, 500) // Max 500 tools
      .filter((t: unknown) => {
        if (typeof t !== "object" || t === null) return false;
        const tool = t as Record<string, unknown>;
        return (
          typeof tool.name === "string" &&
          tool.name.length > 0 &&
          tool.name.length <= 200
        );
      })
      .map((t: unknown) => {
        const tool = t as Record<string, unknown>;
        const result: PapTool = { name: tool.name as string };
        if (typeof tool.description === "string" && tool.description.length <= 1000)
          result.description = tool.description;
        if (typeof tool.endpoint === "string" && tool.endpoint.length <= 500)
          result.endpoint = tool.endpoint;
        if (typeof tool.method === "string" && tool.method.length <= 100)
          result.method = tool.method;
        return result;
      });
  }

  return manifest;
}

// ── Fetch ─────────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 100_000; // 100KB max manifest size

/**
 * Fetch /.well-known/pap-manifest from a URL or origin.
 *
 * Accepts a full URL with `.well-known/` in the path (from link-rel),
 * or an origin/scheme-origin (appends the well-known path).
 *
 * Returns a validated PapManifest or null on any failure.
 * Never throws.
 */
export async function fetchManifest(
  urlOrOrigin: string
): Promise<PapManifest | null> {
  let url: string;
  try {
    // If it looks like a full URL, use it directly.
    // Otherwise, treat as an origin and append well-known path.
    if (urlOrOrigin.startsWith("http://") || urlOrOrigin.startsWith("https://")) {
      const parsed = new URL(urlOrOrigin);
      if (parsed.pathname === "/" || parsed.pathname === "") {
        // Origin only — append well-known path
        url = `${urlOrOrigin}/.well-known/pap-manifest`;
      } else {
        // Full URL with path
        url = urlOrOrigin;
      }
    } else {
      return null; // Invalid input
    }
  } catch {
    return null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
      // Prevent credentials from leaking to the manifest endpoint
      credentials: "omit",
    });

    if (!resp.ok) return null;

    // Check Content-Type
    const contentType = resp.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
      return null;
    }

    // Bound response body size
    const contentLength = resp.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
      return null;
    }

    const data: unknown = await resp.json();
    return validateManifest(data);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

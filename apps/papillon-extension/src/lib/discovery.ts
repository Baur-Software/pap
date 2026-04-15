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

// ── Validation limits ─────────────────────────────────────────────────

const MAX_AGENT_ID_LEN = 1_000;
const MAX_NAME_LEN = 1_000;
const MAX_VERSION_LEN = 100;
const MAX_PUBLIC_KEY_LEN = 5_000;
const MAX_CATEGORIES = 100;
const MAX_CATEGORY_LEN = 200;
const MAX_TOOLS = 500;
const MAX_TOOL_NAME_LEN = 200;
const MAX_TOOL_DESCRIPTION_LEN = 1_000;
const MAX_TOOL_ENDPOINT_LEN = 500;
const MAX_TOOL_METHOD_LEN = 100;

/** Returns true when `val` is a string with length in [minLen, maxLen]. */
function isValidString(val: unknown, minLen: number, maxLen: number): val is string {
  return typeof val === "string" && val.length >= minLen && val.length <= maxLen;
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

  if (!isValidString(obj.agent_id, 1, MAX_AGENT_ID_LEN)) return null;
  if (!isValidString(obj.name, 1, MAX_NAME_LEN)) return null;

  const manifest: PapManifest = {
    agent_id: obj.agent_id,
    name: obj.name,
  };

  if (isValidString(obj.version, 0, MAX_VERSION_LEN)) manifest.version = obj.version;
  if (isValidString(obj.public_key, 0, MAX_PUBLIC_KEY_LEN)) manifest.public_key = obj.public_key;

  if (Array.isArray(obj.categories)) {
    manifest.categories = obj.categories
      .slice(0, MAX_CATEGORIES)
      .filter((c): c is string => typeof c === "string" && c.length <= MAX_CATEGORY_LEN);
  }

  if (Array.isArray(obj.tools)) {
    manifest.tools = (obj.tools as unknown[])
      .slice(0, MAX_TOOLS)
      .filter((t: unknown) => {
        if (typeof t !== "object" || t === null) return false;
        return isValidString((t as Record<string, unknown>).name, 1, MAX_TOOL_NAME_LEN);
      })
      .map((t: unknown) => {
        const tool = t as Record<string, unknown>;
        const result: PapTool = { name: tool.name as string };
        if (isValidString(tool.description, 0, MAX_TOOL_DESCRIPTION_LEN))
          result.description = tool.description;
        if (isValidString(tool.endpoint, 0, MAX_TOOL_ENDPOINT_LEN))
          result.endpoint = tool.endpoint;
        if (isValidString(tool.method, 0, MAX_TOOL_METHOD_LEN))
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

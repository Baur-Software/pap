import { describe, it, expect, vi, afterEach } from "vitest";
import { validateManifest, fetchManifest } from "./discovery.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── validateManifest ───────────────────────────────────────────────────

describe("validateManifest", () => {
  it("valid minimal manifest → returns object", () => {
    const result = validateManifest({ agent_id: "agent-1", name: "Test Agent" });
    expect(result).not.toBeNull();
    expect(result!.agent_id).toBe("agent-1");
    expect(result!.name).toBe("Test Agent");
  });

  it("all optional fields present → included in result", () => {
    const result = validateManifest({
      agent_id: "agent-1",
      name: "Test Agent",
      version: "1.0.0",
      public_key: "-----BEGIN PUBLIC KEY-----",
      tools: [{ name: "search", description: "Search the web", endpoint: "/search", method: "POST" }],
      categories: ["search", "web"],
    });
    expect(result).not.toBeNull();
    expect(result!.version).toBe("1.0.0");
    expect(result!.public_key).toBe("-----BEGIN PUBLIC KEY-----");
    expect(result!.tools).toHaveLength(1);
    expect(result!.tools![0].name).toBe("search");
    expect(result!.categories).toEqual(["search", "web"]);
  });

  it("null input → null", () => {
    expect(validateManifest(null)).toBeNull();
  });

  it("array input → null", () => {
    expect(validateManifest([{ agent_id: "a", name: "b" }])).toBeNull();
  });

  it("non-object input → null", () => {
    expect(validateManifest("string")).toBeNull();
    expect(validateManifest(42)).toBeNull();
  });

  it("missing agent_id → null", () => {
    expect(validateManifest({ name: "Test Agent" })).toBeNull();
  });

  it("empty agent_id → null", () => {
    expect(validateManifest({ agent_id: "", name: "Test Agent" })).toBeNull();
  });

  it("agent_id > 1000 chars → null", () => {
    expect(validateManifest({ agent_id: "a".repeat(1001), name: "Test" })).toBeNull();
  });

  it("agent_id exactly 1000 chars → valid", () => {
    const result = validateManifest({ agent_id: "a".repeat(1000), name: "Test" });
    expect(result).not.toBeNull();
  });

  it("missing name → null", () => {
    expect(validateManifest({ agent_id: "agent-1" })).toBeNull();
  });

  it("empty name → null", () => {
    expect(validateManifest({ agent_id: "agent-1", name: "" })).toBeNull();
  });

  it("name > 1000 chars → null", () => {
    expect(validateManifest({ agent_id: "agent-1", name: "n".repeat(1001) })).toBeNull();
  });

  it("version > 100 chars → omitted from result, manifest still valid", () => {
    const result = validateManifest({
      agent_id: "a",
      name: "b",
      version: "v".repeat(101),
    });
    expect(result).not.toBeNull();
    expect(result!.version).toBeUndefined();
  });

  it("public_key > 5000 chars → omitted from result", () => {
    const result = validateManifest({
      agent_id: "a",
      name: "b",
      public_key: "k".repeat(5001),
    });
    expect(result).not.toBeNull();
    expect(result!.public_key).toBeUndefined();
  });

  it("tools array > 500 items → truncated to 500", () => {
    const tools = Array.from({ length: 600 }, (_, i) => ({ name: `tool-${i}` }));
    const result = validateManifest({ agent_id: "a", name: "b", tools });
    expect(result!.tools).toHaveLength(500);
  });

  it("tool with missing name → filtered out", () => {
    const result = validateManifest({
      agent_id: "a",
      name: "b",
      tools: [{ name: "good-tool" }, { description: "no name here" }],
    });
    expect(result!.tools).toHaveLength(1);
    expect(result!.tools![0].name).toBe("good-tool");
  });

  it("categories array > 100 items → truncated to 100", () => {
    const categories = Array.from({ length: 150 }, (_, i) => `cat-${i}`);
    const result = validateManifest({ agent_id: "a", name: "b", categories });
    expect(result!.categories).toHaveLength(100);
  });

  it("non-string values in categories → filtered out", () => {
    const result = validateManifest({
      agent_id: "a",
      name: "b",
      categories: ["good", 42, null, "also-good"],
    });
    expect(result!.categories).toEqual(["good", "also-good"]);
  });
});

// ── fetchManifest ──────────────────────────────────────────────────────

function mockFetch(
  body: unknown,
  opts: {
    status?: number;
    contentType?: string;
    contentLength?: string;
    throws?: boolean;
  } = {}
) {
  if (opts.throws) {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Network error"))
    );
    return;
  }

  const status = opts.status ?? 200;
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 400,
      status,
      headers: {
        get: (h: string) => {
          if (h === "content-type")
            return opts.contentType ?? "application/json; charset=utf-8";
          if (h === "content-length") return opts.contentLength ?? null;
          return null;
        },
      },
      json: () => Promise.resolve(body),
    })
  );
}

describe("fetchManifest", () => {
  it("happy path: 200 JSON response → validated manifest", async () => {
    mockFetch({ agent_id: "agent-1", name: "Test Agent" });
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).not.toBeNull();
    expect(result!.agent_id).toBe("agent-1");
  });

  it("non-200 response → null", async () => {
    mockFetch({}, { status: 404 });
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).toBeNull();
  });

  it("500 server error → null", async () => {
    mockFetch({}, { status: 500 });
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).toBeNull();
  });

  it("wrong Content-Type (text/html) → null", async () => {
    mockFetch({ agent_id: "a", name: "b" }, { contentType: "text/html" });
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).toBeNull();
  });

  it("content-length > 100KB → null", async () => {
    mockFetch(
      { agent_id: "a", name: "b" },
      { contentLength: String(100_001) }
    );
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).toBeNull();
  });

  it("content-length within limit → not rejected on size alone", async () => {
    mockFetch(
      { agent_id: "a", name: "b" },
      { contentLength: String(100_000) }
    );
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).not.toBeNull();
  });

  it("fetch throws (network error) → null, never throws", async () => {
    mockFetch(null, { throws: true });
    await expect(
      fetchManifest("https://example.com/.well-known/pap-manifest")
    ).resolves.toBeNull();
  });

  it("origin-only URL → appends /.well-known/pap-manifest", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: (h: string) => h === "content-type" ? "application/json" : null },
      json: () => Promise.resolve({ agent_id: "a", name: "b" }),
    });
    vi.stubGlobal("fetch", fetchSpy);

    await fetchManifest("https://example.com");
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://example.com/.well-known/pap-manifest",
      expect.any(Object)
    );
  });

  it("full path URL → used as-is", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: (h: string) => h === "content-type" ? "application/json" : null },
      json: () => Promise.resolve({ agent_id: "a", name: "b" }),
    });
    vi.stubGlobal("fetch", fetchSpy);

    await fetchManifest("https://example.com/custom/manifest-path");
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://example.com/custom/manifest-path",
      expect.any(Object)
    );
  });

  it("non-http/https input → null without fetching", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const result = await fetchManifest("pap://agent.example.com");
    expect(result).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("response body validates to null → returns null", async () => {
    mockFetch({ wrong_field: true }); // missing agent_id and name
    const result = await fetchManifest("https://example.com/.well-known/pap-manifest");
    expect(result).toBeNull();
  });
});

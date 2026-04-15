import { describe, it, expect } from "vitest";
import {
  parsePapUri,
  httpsUrlToPap,
  isPapUri,
  toEndpoint,
  toHttpsEndpoint,
  isBrowserCompatible,
  DEFAULT_PAP_PORT,
} from "./uri.js";

// ── parsePapUri ────────────────────────────────────────────────────────

describe("parsePapUri", () => {
  it("pap:// with host only → native transport and default port", () => {
    const r = parsePapUri("pap://agent.example.com");
    expect(r.host).toBe("agent.example.com");
    expect(r.port).toBe(DEFAULT_PAP_PORT);
    expect(r.path).toBe("/");
    expect(r.transport).toBe("native");
    expect(r.originalUri).toBe("pap://agent.example.com");
  });

  it("pap:// with explicit port", () => {
    const r = parsePapUri("pap://localhost:9000");
    expect(r.host).toBe("localhost");
    expect(r.port).toBe(9000);
    expect(r.transport).toBe("native");
  });

  it("pap:// with host:port/path preserves path", () => {
    const r = parsePapUri("pap://agent.example.com:7890/search");
    expect(r.host).toBe("agent.example.com");
    expect(r.port).toBe(7890);
    expect(r.path).toBe("/search");
  });

  it("pap+https:// → transport = https", () => {
    const r = parsePapUri("pap+https://agent.example.com/v1");
    expect(r.transport).toBe("https");
    expect(r.host).toBe("agent.example.com");
    expect(r.path).toBe("/v1");
  });

  it("pap+wss:// → transport = wss", () => {
    const r = parsePapUri("pap+wss://agent.example.com");
    expect(r.transport).toBe("wss");
  });

  it("bare host:port → treated as native", () => {
    const r = parsePapUri("localhost:8080");
    expect(r.transport).toBe("native");
    expect(r.host).toBe("localhost");
    expect(r.port).toBe(8080);
  });

  it("bare host → native, default port", () => {
    const r = parsePapUri("myagent");
    expect(r.transport).toBe("native");
    expect(r.port).toBe(DEFAULT_PAP_PORT);
  });

  it("throws on https://", () => {
    expect(() => parsePapUri("https://example.com")).toThrow();
  });

  it("throws on http://", () => {
    expect(() => parsePapUri("http://example.com")).toThrow();
  });

  it("throws on ws://", () => {
    expect(() => parsePapUri("ws://example.com")).toThrow();
  });

  it("throws on wss://", () => {
    expect(() => parsePapUri("wss://example.com")).toThrow();
  });

  it("throws on unknown pap+foo:// scheme", () => {
    expect(() => parsePapUri("pap+grpc://example.com")).toThrow();
  });

  it("throws on empty pap:// URI", () => {
    expect(() => parsePapUri("pap://")).toThrow();
  });

  it("pap:// with path and query string", () => {
    const r = parsePapUri("pap://agent.example.com:7890/search?q=flights");
    expect(r.path).toBe("/search?q=flights");
  });

  it("pap+https:// with non-default port", () => {
    const r = parsePapUri("pap+https://agent.example.com:8443/api");
    expect(r.port).toBe(8443);
    expect(r.transport).toBe("https");
  });
});

// ── httpsUrlToPap ──────────────────────────────────────────────────────

describe("httpsUrlToPap", () => {
  it("basic https:// → pap+https://", () => {
    expect(httpsUrlToPap("https://example.com")).toBe("pap+https://example.com/");
  });

  it("preserves path", () => {
    expect(httpsUrlToPap("https://example.com/book/123")).toBe(
      "pap+https://example.com/book/123"
    );
  });

  it("preserves query string", () => {
    expect(httpsUrlToPap("https://example.com/search?q=flights&date=2026-04-15")).toBe(
      "pap+https://example.com/search?q=flights&date=2026-04-15"
    );
  });

  it("omits default port 443", () => {
    expect(httpsUrlToPap("https://example.com:443/path")).toBe(
      "pap+https://example.com/path"
    );
  });

  it("includes non-default port", () => {
    expect(httpsUrlToPap("https://example.com:8443/api")).toBe(
      "pap+https://example.com:8443/api"
    );
  });

  it("wss transport option", () => {
    expect(httpsUrlToPap("https://example.com/ws", "wss")).toBe(
      "pap+wss://example.com/ws"
    );
  });

  it("throws on http:// input", () => {
    expect(() => httpsUrlToPap("http://example.com")).toThrow();
  });

  it("throws on pap+https:// input", () => {
    expect(() => httpsUrlToPap("pap+https://example.com")).toThrow();
  });
});

// ── isPapUri ───────────────────────────────────────────────────────────

describe("isPapUri", () => {
  it("pap:// → true", () => expect(isPapUri("pap://agent.example.com")).toBe(true));
  it("pap+https:// → true", () => expect(isPapUri("pap+https://example.com")).toBe(true));
  it("pap+wss:// → true", () => expect(isPapUri("pap+wss://example.com")).toBe(true));
  it("https:// → false", () => expect(isPapUri("https://example.com")).toBe(false));
  it("empty string → false", () => expect(isPapUri("")).toBe(false));
  it("trims leading whitespace before checking", () => {
    expect(isPapUri("  pap://agent.example.com")).toBe(true);
  });
});

// ── toEndpoint ────────────────────────────────────────────────────────

describe("toEndpoint", () => {
  it("native → https endpoint", () => {
    const u = parsePapUri("pap://agent.example.com:7890");
    expect(toEndpoint(u)).toBe("https://agent.example.com:7890");
  });

  it("https → https endpoint", () => {
    const u = parsePapUri("pap+https://agent.example.com:8443");
    expect(toEndpoint(u)).toBe("https://agent.example.com:8443");
  });

  it("wss → wss endpoint", () => {
    const u = parsePapUri("pap+wss://agent.example.com:9000");
    expect(toEndpoint(u)).toBe("wss://agent.example.com:9000");
  });
});

// ── toHttpsEndpoint ───────────────────────────────────────────────────

describe("toHttpsEndpoint", () => {
  it("always returns https:// regardless of transport", () => {
    const u = parsePapUri("pap+wss://agent.example.com:9000");
    expect(toHttpsEndpoint(u)).toBe("https://agent.example.com:9000");
  });
});

// ── isBrowserCompatible ───────────────────────────────────────────────

describe("isBrowserCompatible", () => {
  it("native → false", () => {
    expect(isBrowserCompatible(parsePapUri("pap://localhost:7890"))).toBe(false);
  });

  it("https → true", () => {
    expect(isBrowserCompatible(parsePapUri("pap+https://example.com"))).toBe(true);
  });

  it("wss → true", () => {
    expect(isBrowserCompatible(parsePapUri("pap+wss://example.com"))).toBe(true);
  });
});

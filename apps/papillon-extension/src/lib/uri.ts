/**
 * PAP URI parser — TypeScript port of crates/pap-federation/src/resolve.rs
 *
 * Parses `pap://`, `pap+https://`, and `pap+wss://` URIs into structured
 * endpoints. PAP is its own protocol; compound schemes declare a transport
 * binding for environments where native transport isn't available (browsers).
 */

export const DEFAULT_PAP_PORT = 7890;

export type PapTransport = "native" | "https" | "wss";

export interface PapUrl {
  /** Original URI as entered/clicked */
  readonly originalUri: string;
  readonly host: string;
  readonly port: number;
  readonly path: string;
  readonly transport: PapTransport;
}

/**
 * Parse a PAP URI.
 *
 * Accepts:
 * - `pap://host:port/path`        — native transport
 * - `pap+https://host:port/path`  — HTTPS binding
 * - `pap+wss://host:port/path`    — WSS binding
 * - `pap://host`                  — native, default port 7890
 * - Bare `host:port` or `host`    — native, for convenience
 *
 * Rejects raw `http://`, `https://`, `ws://`, `wss://`.
 */
export function parsePapUri(uri: string): PapUrl {
  const trimmed = uri.trim();

  // Reject raw transport schemes — PAP is its own protocol.
  for (const scheme of ["http://", "https://", "ws://", "wss://"]) {
    if (trimmed.startsWith(scheme)) {
      throw new Error(
        `'${trimmed}' is not a PAP URL — use pap://, pap+https://, or pap+wss://`
      );
    }
  }

  let transport: PapTransport;
  let remainder: string;

  if (trimmed.startsWith("pap+https://")) {
    transport = "https";
    remainder = trimmed.slice("pap+https://".length);
  } else if (trimmed.startsWith("pap+wss://")) {
    transport = "wss";
    remainder = trimmed.slice("pap+wss://".length);
  } else if (trimmed.startsWith("pap+")) {
    throw new Error(`unknown PAP transport binding: '${trimmed}'`);
  } else if (trimmed.startsWith("pap://")) {
    transport = "native";
    remainder = trimmed.slice("pap://".length);
  } else {
    // Bare host:port — treat as native
    transport = "native";
    remainder = trimmed;
  }

  if (!remainder || remainder === "/") {
    throw new Error("empty PAP URL");
  }

  // Split host:port from path
  const slashIdx = remainder.indexOf("/");
  let hostport: string;
  let path: string;

  if (slashIdx === -1) {
    hostport = remainder.replace(/\/+$/, "");
    path = "/";
  } else {
    hostport = remainder.slice(0, slashIdx);
    path = remainder.slice(slashIdx);
  }

  // Parse host:port
  let host: string;
  let port: number;

  const lastColon = hostport.lastIndexOf(":");
  if (lastColon !== -1) {
    const portStr = hostport.slice(lastColon + 1);
    const parsed = parseInt(portStr, 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      host = hostport.slice(0, lastColon);
      port = parsed;
    } else {
      host = hostport;
      port = DEFAULT_PAP_PORT;
    }
  } else {
    host = hostport;
    port = DEFAULT_PAP_PORT;
  }

  return { originalUri: uri, host, port, path, transport };
}

/** The transport endpoint URL for fetch/WebSocket. */
export function toEndpoint(url: PapUrl): string {
  switch (url.transport) {
    case "native":
    case "https":
      return `https://${url.host}:${url.port}`;
    case "wss":
      return `wss://${url.host}:${url.port}`;
  }
}

/** Always returns the HTTPS endpoint, regardless of transport. */
export function toHttpsEndpoint(url: PapUrl): string {
  return `https://${url.host}:${url.port}`;
}

/** Whether this URI uses a browser-compatible transport. */
export function isBrowserCompatible(url: PapUrl): boolean {
  return url.transport === "https" || url.transport === "wss";
}

/** Detect PAP URIs in a string (href attribute, address bar input, etc.) */
export function isPapUri(str: string): boolean {
  const t = str.trim();
  return (
    t.startsWith("pap://") ||
    t.startsWith("pap+https://") ||
    t.startsWith("pap+wss://")
  );
}

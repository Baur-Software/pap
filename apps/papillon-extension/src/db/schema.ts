/**
 * IndexedDB schema for the PAP browser extension.
 *
 * The schema mirrors the PAP protocol data model. All on-disk identifiers
 * use string DIDs and ISO-8601 timestamps so JSON round-trips are lossless.
 *
 * Store layout:
 *   sessions     — active/historical PAP sessions keyed by session DID
 *   mandates     — capability tokens scoped to a session
 *   credentials  — W3C VCs / SD-JWT credentials held by the principal
 *   episodes     — audit log of per-session actions and outcomes
 */

// ── Domain types ──────────────────────────────────────────────────────────────

export type SessionStatus = "active" | "degraded" | "readonly" | "suspended" | "closed";

/** A PAP session established between the principal and an agent. */
export interface Session {
  /** UUID v4 — stable, opaque row identifier */
  id: string;
  /** Ephemeral DID generated for this session — never reused */
  session_did: string;
  /** DID of the agent that accepted the handshake */
  agent_did: string;
  /** DID of the human principal who initiated the session */
  principal_did: string;
  /** Requested capability scope (PAP scope string) */
  scope: string;
  /** ISO-8601 creation timestamp */
  created_at: string;
  /** ISO-8601 expiry timestamp (from mandate TTL) */
  expires_at: string;
  /** Progressive decay state — starts Active */
  status: SessionStatus;
}

/** A mandate (capability token) bound to a session. */
export interface Mandate {
  /** UUID v4 */
  id: string;
  /** Raw JSON of the CapabilityToken — stored verbatim, never re-serialised */
  mandate_json: string;
  /** DID of the principal who issued the mandate */
  principal_did: string;
  /** Foreign key → sessions.id */
  session_id: string;
  /** ISO-8601 timestamp */
  issued_at: string;
  /** ISO-8601 expiry — must match the embedded mandate TTL */
  expires_at: string;
}

/** A W3C Verifiable Credential or SD-JWT held by the principal. */
export interface Credential {
  /** UUID v4 */
  id: string;
  /** Raw credential JSON — never innerHTML-rendered, text only */
  credential_json: string;
  /** DID of the credential subject */
  subject_did: string;
  /** ISO-8601 issuance timestamp */
  issued_at: string;
  /** ISO-8601 expiry; null = non-expiring */
  expires_at: string | null;
}

/** A single audited action within a session. */
export interface Episode {
  /** UUID v4 */
  id: string;
  /** Foreign key → sessions.id */
  session_id: string;
  /** Short action label (e.g. "token_presented", "receipt_co_signed") */
  action: string;
  /** Outcome description — property references only, never values */
  outcome: string;
  /** ISO-8601 timestamp of this event */
  timestamp: string;
}

// ── Schema definition ─────────────────────────────────────────────────────────

export const DB_NAME = "pap_extension";
export const DB_VERSION = 1;

/**
 * Called inside an `onupgradeneeded` handler.
 * Creates all object stores and their indexes for a fresh DB.
 */
export function createSchema(db: IDBDatabase): void {
  // ── sessions ───────────────────────────────────────────────────────────────
  const sessionsStore = db.createObjectStore("sessions", { keyPath: "id" });
  sessionsStore.createIndex("by_session_did", "session_did", { unique: true });
  sessionsStore.createIndex("by_principal_did", "principal_did");
  sessionsStore.createIndex("by_status", "status");
  sessionsStore.createIndex("by_expires_at", "expires_at");

  // ── mandates ──────────────────────────────────────────────────────────────
  const mandatesStore = db.createObjectStore("mandates", { keyPath: "id" });
  mandatesStore.createIndex("by_session_id", "session_id");
  mandatesStore.createIndex("by_principal_did", "principal_did");
  mandatesStore.createIndex("by_expires_at", "expires_at");

  // ── credentials ──────────────────────────────────────────────────────────
  const credentialsStore = db.createObjectStore("credentials", { keyPath: "id" });
  credentialsStore.createIndex("by_subject_did", "subject_did");
  credentialsStore.createIndex("by_expires_at", "expires_at");

  // ── episodes ──────────────────────────────────────────────────────────────
  const episodesStore = db.createObjectStore("episodes", { keyPath: "id" });
  episodesStore.createIndex("by_session_id", "session_id");
  episodesStore.createIndex("by_timestamp", "timestamp");
}

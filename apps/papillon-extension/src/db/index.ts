/**
 * Public API for the PAP extension IndexedDB persistence layer.
 *
 * Usage:
 *
 *   import { PapDB } from "../db/index.js";
 *
 *   const db = await PapDB.open();
 *   await db.saveSession(session);
 *   const active = await db.listActiveSessions();
 */

export { PapDB } from "./db.js";
export type {
  Session,
  SessionStatus,
  Mandate,
  Credential,
  Episode,
} from "./schema.js";
export { DB_NAME, DB_VERSION } from "./schema.js";

/**
 * Tests for PapDB — IndexedDB persistence layer.
 *
 * Uses `fake-indexeddb` to provide a spec-compliant in-memory IndexedDB
 * implementation without requiring a browser or service worker environment.
 *
 * Each test gets a completely fresh IDBFactory instance to guarantee full
 * test isolation — no state leaks between tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
// fake-indexeddb v6 ships its own IDBKeyRange implementation; import it so
// the IDBKeyRange constructor used inside PapDB resolves correctly in Node.
import { IDBFactory, IDBKeyRange as FakeIDBKeyRange } from "fake-indexeddb";
import { PapDB } from "./db.js";
import type { Session, Mandate, Credential, Episode } from "./schema.js";

// Inject the fake IDBKeyRange into the global scope so that db.ts can
// reference IDBKeyRange without a browser.
Object.assign(globalThis, { IDBKeyRange: FakeIDBKeyRange });

// ── Fixture factories ─────────────────────────────────────────────────────────

function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    id: crypto.randomUUID(),
    session_did: `did:key:z${crypto.randomUUID().replace(/-/g, "")}`,
    agent_did: "did:key:zagent000000",
    principal_did: "did:key:zprincipal00",
    scope: "search",
    created_at: "2025-01-01T00:00:00.000Z",
    expires_at: "2025-12-31T23:59:59.000Z",
    status: "active",
    ...overrides,
  };
}

function makeMandate(sessionId: string, overrides: Partial<Mandate> = {}): Mandate {
  return {
    id: crypto.randomUUID(),
    mandate_json: JSON.stringify({ type: "CapabilityToken", scope: "search" }),
    principal_did: "did:key:zprincipal00",
    session_id: sessionId,
    issued_at: "2025-01-01T00:00:00.000Z",
    expires_at: "2025-12-31T23:59:59.000Z",
    ...overrides,
  };
}

function makeCredential(subjectDid: string, overrides: Partial<Credential> = {}): Credential {
  return {
    id: crypto.randomUUID(),
    credential_json: JSON.stringify({ "@context": ["https://www.w3.org/2018/credentials/v1"] }),
    subject_did: subjectDid,
    issued_at: "2025-01-01T00:00:00.000Z",
    expires_at: "2025-12-31T23:59:59.000Z",
    ...overrides,
  };
}

function makeEpisode(sessionId: string, overrides: Partial<Episode> = {}): Episode {
  return {
    id: crypto.randomUUID(),
    session_id: sessionId,
    action: "token_presented",
    outcome: "accepted",
    timestamp: "2025-06-15T12:00:00.000Z",
    ...overrides,
  };
}

// ── Helper: fresh DB per test ─────────────────────────────────────────────────

function freshDB(): Promise<PapDB> {
  return PapDB.open(new IDBFactory());
}

// ── Test suites ───────────────────────────────────────────────────────────────

describe("PapDB.open", () => {
  it("opens a new database without error", async () => {
    const db = await freshDB();
    expect(db).toBeInstanceOf(PapDB);
    db.close();
  });

  it("can be opened multiple times (separate instances)", async () => {
    const db1 = await freshDB();
    const db2 = await freshDB();
    expect(db1).toBeInstanceOf(PapDB);
    expect(db2).toBeInstanceOf(PapDB);
    db1.close();
    db2.close();
  });
});

describe("PapDB — sessions", () => {
  let db: PapDB;

  beforeEach(async () => {
    db = await freshDB();
  });

  afterEach(() => {
    db.close();
  });

  it("saves and retrieves a session by id", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const retrieved = await db.getSession(session.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(session.id);
    expect(retrieved!.session_did).toBe(session.session_did);
    expect(retrieved!.principal_did).toBe(session.principal_did);
    expect(retrieved!.status).toBe("active");
  });

  it("returns null for a non-existent session id", async () => {
    const result = await db.getSession(crypto.randomUUID());
    expect(result).toBeNull();
  });

  it("overwrites an existing session on put (upsert semantics)", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const updated: Session = { ...session, status: "degraded" };
    await db.saveSession(updated);

    const retrieved = await db.getSession(session.id);
    expect(retrieved!.status).toBe("degraded");
  });

  it("lists only active sessions", async () => {
    const active1 = makeSession({ status: "active" });
    const active2 = makeSession({ status: "active" });
    const closed = makeSession({ status: "closed" });
    const suspended = makeSession({ status: "suspended" });

    await db.saveSession(active1);
    await db.saveSession(active2);
    await db.saveSession(closed);
    await db.saveSession(suspended);

    const active = await db.listActiveSessions();
    const ids = active.map((s) => s.id);

    expect(ids).toContain(active1.id);
    expect(ids).toContain(active2.id);
    expect(ids).not.toContain(closed.id);
    expect(ids).not.toContain(suspended.id);
  });

  it("returns an empty array when no active sessions exist", async () => {
    const session = makeSession({ status: "closed" });
    await db.saveSession(session);

    const active = await db.listActiveSessions();
    expect(active).toHaveLength(0);
  });

  it("updateSessionStatus transitions a session to the new status", async () => {
    const session = makeSession({ status: "active" });
    await db.saveSession(session);

    await db.updateSessionStatus(session.id, "readonly");

    const retrieved = await db.getSession(session.id);
    expect(retrieved!.status).toBe("readonly");
  });

  it("updateSessionStatus is a no-op for a non-existent id", async () => {
    // Should not throw
    await expect(
      db.updateSessionStatus(crypto.randomUUID(), "suspended")
    ).resolves.toBeUndefined();
  });

  it("stores all progressive decay statuses", async () => {
    const statuses: Session["status"][] = [
      "active",
      "degraded",
      "readonly",
      "suspended",
      "closed",
    ];

    for (const status of statuses) {
      const session = makeSession({ status });
      await db.saveSession(session);
      const retrieved = await db.getSession(session.id);
      expect(retrieved!.status).toBe(status);
    }
  });
});

describe("PapDB — mandates", () => {
  let db: PapDB;

  beforeEach(async () => {
    db = await freshDB();
  });

  afterEach(() => {
    db.close();
  });

  it("saves and retrieves mandates by session id", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const mandate1 = makeMandate(session.id);
    const mandate2 = makeMandate(session.id);
    await db.saveMandate(mandate1);
    await db.saveMandate(mandate2);

    const mandates = await db.getMandatesBySession(session.id);
    expect(mandates).toHaveLength(2);
    const ids = mandates.map((m) => m.id);
    expect(ids).toContain(mandate1.id);
    expect(ids).toContain(mandate2.id);
  });

  it("returns empty array for a session with no mandates", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const mandates = await db.getMandatesBySession(session.id);
    expect(mandates).toHaveLength(0);
  });

  it("does not return mandates from a different session", async () => {
    const session1 = makeSession();
    const session2 = makeSession();
    await db.saveSession(session1);
    await db.saveSession(session2);

    const mandate = makeMandate(session1.id);
    await db.saveMandate(mandate);

    const mandates = await db.getMandatesBySession(session2.id);
    expect(mandates).toHaveLength(0);
  });

  it("stores the mandate_json verbatim", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const rawJson = JSON.stringify({
      type: "CapabilityToken",
      scope: "search:read",
      ttl: 3600,
      constraints: { max_results: 10 },
    });
    const mandate = makeMandate(session.id, { mandate_json: rawJson });
    await db.saveMandate(mandate);

    const [retrieved] = await db.getMandatesBySession(session.id);
    expect(retrieved.mandate_json).toBe(rawJson);
  });
});

describe("PapDB — credentials", () => {
  let db: PapDB;

  beforeEach(async () => {
    db = await freshDB();
  });

  afterEach(() => {
    db.close();
  });

  it("saves and retrieves credentials by subject DID", async () => {
    const subjectDid = "did:key:zsubject0001";
    const cred1 = makeCredential(subjectDid);
    const cred2 = makeCredential(subjectDid);
    await db.saveCredential(cred1);
    await db.saveCredential(cred2);

    const credentials = await db.getCredentialsBySubject(subjectDid);
    expect(credentials).toHaveLength(2);
    const ids = credentials.map((c) => c.id);
    expect(ids).toContain(cred1.id);
    expect(ids).toContain(cred2.id);
  });

  it("returns empty array for an unknown subject DID", async () => {
    const credentials = await db.getCredentialsBySubject("did:key:zunknown");
    expect(credentials).toHaveLength(0);
  });

  it("stores non-expiring credentials (expires_at: null)", async () => {
    const cred = makeCredential("did:key:zprincipal00", { expires_at: null });
    await db.saveCredential(cred);

    const [retrieved] = await db.getCredentialsBySubject(cred.subject_did);
    expect(retrieved.expires_at).toBeNull();
  });

  it("does not return credentials for a different subject DID", async () => {
    const cred = makeCredential("did:key:zsubjectA");
    await db.saveCredential(cred);

    const result = await db.getCredentialsBySubject("did:key:zsubjectB");
    expect(result).toHaveLength(0);
  });
});

describe("PapDB — episodes", () => {
  let db: PapDB;

  beforeEach(async () => {
    db = await freshDB();
  });

  afterEach(() => {
    db.close();
  });

  it("records and retrieves episodes for a session", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const ep1 = makeEpisode(session.id, {
      action: "token_presented",
      timestamp: "2025-06-15T12:00:00.000Z",
    });
    const ep2 = makeEpisode(session.id, {
      action: "receipt_co_signed",
      timestamp: "2025-06-15T12:01:00.000Z",
    });
    await db.recordEpisode(ep1);
    await db.recordEpisode(ep2);

    const episodes = await db.getEpisodesBySession(session.id);
    expect(episodes).toHaveLength(2);
    expect(episodes[0].action).toBe("token_presented");
    expect(episodes[1].action).toBe("receipt_co_signed");
  });

  it("returns episodes in ascending timestamp order", async () => {
    const session = makeSession();
    await db.saveSession(session);

    // Insert in reverse order to verify sort
    const ep3 = makeEpisode(session.id, { action: "c", timestamp: "2025-06-15T12:02:00.000Z" });
    const ep1 = makeEpisode(session.id, { action: "a", timestamp: "2025-06-15T12:00:00.000Z" });
    const ep2 = makeEpisode(session.id, { action: "b", timestamp: "2025-06-15T12:01:00.000Z" });

    await db.recordEpisode(ep3);
    await db.recordEpisode(ep1);
    await db.recordEpisode(ep2);

    const episodes = await db.getEpisodesBySession(session.id);
    expect(episodes.map((e) => e.action)).toEqual(["a", "b", "c"]);
  });

  it("returns empty array for a session with no episodes", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const episodes = await db.getEpisodesBySession(session.id);
    expect(episodes).toHaveLength(0);
  });

  it("does not return episodes from a different session", async () => {
    const session1 = makeSession();
    const session2 = makeSession();
    await db.saveSession(session1);
    await db.saveSession(session2);

    const episode = makeEpisode(session1.id);
    await db.recordEpisode(episode);

    const episodes = await db.getEpisodesBySession(session2.id);
    expect(episodes).toHaveLength(0);
  });

  it("stores outcome as property reference, not credential value", async () => {
    const session = makeSession();
    await db.saveSession(session);

    // Outcome is a property reference string, never a raw credential value
    const ep = makeEpisode(session.id, {
      action: "receipt_co_signed",
      outcome: "receipt.co_signatures:2",
    });
    await db.recordEpisode(ep);

    const [retrieved] = await db.getEpisodesBySession(session.id);
    expect(retrieved.outcome).toBe("receipt.co_signatures:2");
  });
});

describe("PapDB — purgeExpired", () => {
  let db: PapDB;

  beforeEach(async () => {
    db = await freshDB();
  });

  afterEach(() => {
    db.close();
  });

  it("deletes expired sessions and returns correct count", async () => {
    const expired = makeSession({
      expires_at: "2024-01-01T00:00:00.000Z",
      status: "active",
    });
    const valid = makeSession({
      expires_at: "2099-01-01T00:00:00.000Z",
      status: "active",
    });

    await db.saveSession(expired);
    await db.saveSession(valid);

    const deleted = await db.purgeExpired("2025-06-01T00:00:00.000Z");
    expect(deleted).toBeGreaterThanOrEqual(1);

    const expiredResult = await db.getSession(expired.id);
    expect(expiredResult).toBeNull();

    const validResult = await db.getSession(valid.id);
    expect(validResult).not.toBeNull();
  });

  it("deletes expired mandates", async () => {
    const session = makeSession();
    await db.saveSession(session);

    const expiredMandate = makeMandate(session.id, {
      expires_at: "2024-01-01T00:00:00.000Z",
    });
    const validMandate = makeMandate(session.id, {
      expires_at: "2099-01-01T00:00:00.000Z",
    });

    await db.saveMandate(expiredMandate);
    await db.saveMandate(validMandate);

    await db.purgeExpired("2025-06-01T00:00:00.000Z");

    const mandates = await db.getMandatesBySession(session.id);
    const ids = mandates.map((m) => m.id);
    expect(ids).not.toContain(expiredMandate.id);
    expect(ids).toContain(validMandate.id);
  });

  it("does not purge non-expiring credentials (expires_at: null)", async () => {
    const nonExpiring = makeCredential("did:key:zprincipal00", {
      expires_at: null,
    });
    await db.saveCredential(nonExpiring);

    await db.purgeExpired("2099-01-01T00:00:00.000Z");

    const retrieved = await db.getCredentialsBySubject(nonExpiring.subject_did);
    expect(retrieved.some((c) => c.id === nonExpiring.id)).toBe(true);
  });

  it("returns 0 when nothing has expired", async () => {
    const session = makeSession({ expires_at: "2099-01-01T00:00:00.000Z" });
    await db.saveSession(session);

    const deleted = await db.purgeExpired("2025-06-01T00:00:00.000Z");
    expect(deleted).toBe(0);
  });
});

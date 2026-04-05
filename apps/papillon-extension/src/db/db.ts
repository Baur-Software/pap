/**
 * PapDB — IndexedDB persistence layer for the PAP browser extension.
 *
 * All operations are wrapped in individual read-write or read-only
 * transactions. There is no connection pooling — the single IDBDatabase
 * handle is reused across operations after the initial `open()` call.
 *
 * Design constraints:
 * - No external library dependencies — native IndexedDB API only.
 * - TypeScript strict mode throughout.
 * - Never stores credential values — only JSON blobs + property references.
 */

import {
  DB_NAME,
  DB_VERSION,
  createSchema,
  type Session,
  type Mandate,
  type Credential,
  type Episode,
} from "./schema.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Wrap an IDBRequest in a Promise.
 * Rejects with the request error if the request fails.
 */
function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Wrap an IDBTransaction completion in a Promise.
 * Resolves when the transaction commits; rejects on abort or error.
 */
function transactionComplete(tx: IDBTransaction): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(new Error("Transaction aborted"));
  });
}

// ── PapDB ─────────────────────────────────────────────────────────────────────

export class PapDB {
  private readonly db: IDBDatabase;

  private constructor(db: IDBDatabase) {
    this.db = db;
  }

  // ── Lifecycle ───────────────────────────────────────────────────────────────

  /**
   * Open (or create) the PAP IndexedDB database.
   *
   * Runs schema migration via `onupgradeneeded` if the database is new or
   * the stored version is below `DB_VERSION`.
   *
   * @param factory - IDBFactory to use. Defaults to the global `indexedDB`.
   *   Pass a `fake-indexeddb` instance in tests for full isolation.
   */
  static open(factory: IDBFactory = indexedDB): Promise<PapDB> {
    return new Promise<PapDB>((resolve, reject) => {
      const request = factory.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        const oldVersion = event.oldVersion;

        if (oldVersion < 1) {
          // Fresh install — create all stores.
          createSchema(db);
        }
        // Future migrations: if (oldVersion < 2) { ... }
      };

      request.onsuccess = () => resolve(new PapDB(request.result));
      request.onerror = () => reject(request.error);
      request.onblocked = () =>
        reject(new Error("IndexedDB upgrade blocked by an open connection"));
    });
  }

  /** Close the underlying IDBDatabase connection. */
  close(): void {
    this.db.close();
  }

  // ── Sessions ────────────────────────────────────────────────────────────────

  /** Persist (insert or update) a session record. */
  async saveSession(session: Session): Promise<void> {
    const tx = this.db.transaction("sessions", "readwrite");
    const store = tx.objectStore("sessions");
    store.put(session);
    await transactionComplete(tx);
  }

  /** Retrieve a session by its UUID id. Returns null if not found. */
  async getSession(id: string): Promise<Session | null> {
    const tx = this.db.transaction("sessions", "readonly");
    const store = tx.objectStore("sessions");
    const result = await requestToPromise<Session | undefined>(store.get(id));
    return result ?? null;
  }

  /**
   * List all sessions whose `status` is "active".
   *
   * Uses the `by_status` index for an efficient range scan rather than a
   * full table scan.
   */
  async listActiveSessions(): Promise<Session[]> {
    const tx = this.db.transaction("sessions", "readonly");
    const store = tx.objectStore("sessions");
    const index = store.index("by_status");
    const results = await requestToPromise<Session[]>(
      index.getAll(IDBKeyRange.only("active"))
    );
    return results;
  }

  /**
   * Update the status of a session (progressive decay support).
   * No-ops if the session does not exist.
   */
  async updateSessionStatus(
    id: string,
    status: Session["status"]
  ): Promise<void> {
    const tx = this.db.transaction("sessions", "readwrite");
    const store = tx.objectStore("sessions");
    const existing = await requestToPromise<Session | undefined>(store.get(id));
    if (existing) {
      store.put({ ...existing, status });
    }
    await transactionComplete(tx);
  }

  // ── Mandates ────────────────────────────────────────────────────────────────

  /** Persist (insert or update) a mandate record. */
  async saveMandate(mandate: Mandate): Promise<void> {
    const tx = this.db.transaction("mandates", "readwrite");
    const store = tx.objectStore("mandates");
    store.put(mandate);
    await transactionComplete(tx);
  }

  /** Retrieve all mandates associated with a given session id. */
  async getMandatesBySession(sessionId: string): Promise<Mandate[]> {
    const tx = this.db.transaction("mandates", "readonly");
    const store = tx.objectStore("mandates");
    const index = store.index("by_session_id");
    const results = await requestToPromise<Mandate[]>(
      index.getAll(IDBKeyRange.only(sessionId))
    );
    return results;
  }

  // ── Credentials ─────────────────────────────────────────────────────────────

  /** Persist (insert or update) a credential record. */
  async saveCredential(credential: Credential): Promise<void> {
    const tx = this.db.transaction("credentials", "readwrite");
    const store = tx.objectStore("credentials");
    store.put(credential);
    await transactionComplete(tx);
  }

  /** Retrieve all credentials for a given subject DID. */
  async getCredentialsBySubject(subjectDid: string): Promise<Credential[]> {
    const tx = this.db.transaction("credentials", "readonly");
    const store = tx.objectStore("credentials");
    const index = store.index("by_subject_did");
    const results = await requestToPromise<Credential[]>(
      index.getAll(IDBKeyRange.only(subjectDid))
    );
    return results;
  }

  // ── Episodes ────────────────────────────────────────────────────────────────

  /** Append a new episode to the audit log. */
  async recordEpisode(episode: Episode): Promise<void> {
    const tx = this.db.transaction("episodes", "readwrite");
    const store = tx.objectStore("episodes");
    store.put(episode);
    await transactionComplete(tx);
  }

  /** Retrieve all episodes for a given session, ordered by insertion order. */
  async getEpisodesBySession(sessionId: string): Promise<Episode[]> {
    const tx = this.db.transaction("episodes", "readonly");
    const store = tx.objectStore("episodes");
    const index = store.index("by_session_id");
    const results = await requestToPromise<Episode[]>(
      index.getAll(IDBKeyRange.only(sessionId))
    );
    // Sort by timestamp ascending; ISO-8601 strings are lexicographically ordered.
    results.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return results;
  }

  // ── Maintenance ─────────────────────────────────────────────────────────────

  /**
   * Purge expired sessions, mandates, and credentials.
   *
   * Compares stored `expires_at` ISO-8601 strings against the provided
   * `now` timestamp (defaults to the current wall-clock time).
   *
   * Returns the number of records deleted.
   */
  async purgeExpired(now: string = new Date().toISOString()): Promise<number> {
    let deleted = 0;

    // Sessions
    deleted += await this._purgeExpiredFromStore("sessions", now);
    // Mandates
    deleted += await this._purgeExpiredFromStore("mandates", now);
    // Credentials (expires_at is nullable — skip nulls)
    deleted += await this._purgeExpiredCredentials(now);

    return deleted;
  }

  private async _purgeExpiredFromStore(
    storeName: "sessions" | "mandates",
    now: string
  ): Promise<number> {
    const tx = this.db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const index = store.index("by_expires_at");

    // IDBKeyRange.upperBound(now, false) matches everything with expires_at <= now
    const expired = await requestToPromise<{ id: string; expires_at: string }[]>(
      index.getAll(IDBKeyRange.upperBound(now, false))
    );

    for (const record of expired) {
      store.delete(record.id);
    }

    await transactionComplete(tx);
    return expired.length;
  }

  private async _purgeExpiredCredentials(now: string): Promise<number> {
    const tx = this.db.transaction("credentials", "readwrite");
    const store = tx.objectStore("credentials");
    const index = store.index("by_expires_at");

    // Only fetch records that have an expires_at value (non-null, non-empty)
    // and where it is <= now.
    const expired = await requestToPromise<Credential[]>(
      index.getAll(IDBKeyRange.upperBound(now, false))
    );

    // Filter out any that were stored with a null/empty expires_at (edge case
    // if the index was populated with null — IDB stores null values at the
    // low end of the key range).
    const trulyExpired = expired.filter(
      (c) => c.expires_at !== null && c.expires_at !== ""
    );

    for (const c of trulyExpired) {
      store.delete(c.id);
    }

    await transactionComplete(tx);
    return trulyExpired.length;
  }
}

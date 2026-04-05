/**
 * IndexedDB-backed storage for CryptoKey objects.
 *
 * CryptoKey objects support structured clone (IDB stores them natively).
 * Non-extractable CryptoKeys remain opaque even in IDB — the browser
 * enforces that the key material cannot be exported via any API.
 *
 * Replaces the AES-256-GCM encryption layer in storage.ts for principal keys
 * when SubtleCrypto Ed25519 is available.
 */

const DB_NAME = "pap_keystore";
const DB_VERSION = 1;
const STORE_NAME = "keys";
const PRINCIPAL_KEY_ID = "principal";

export interface StoredKeypair {
  id: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** Cached 32-byte raw public key (avoids WASM dependency on load). */
  publicKeyRaw: Uint8Array;
  /** Cached did:key string (avoids WASM dependency on load). */
  did: string;
  createdAt: number;
  /** Tracks migration provenance when migrated from legacy storage. */
  migratedFrom?: "aes-gcm";
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** Store a principal keypair in IndexedDB. */
export async function storePrincipalKeypair(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  publicKeyRaw: Uint8Array,
  did: string,
  migratedFrom?: "aes-gcm"
): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  const record: StoredKeypair = {
    id: PRINCIPAL_KEY_ID,
    privateKey,
    publicKey,
    publicKeyRaw,
    did,
    createdAt: Date.now(),
    ...(migratedFrom ? { migratedFrom } : {}),
  };
  store.put(record);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };
  });
}

/** Load the principal keypair. Returns null if none stored. */
export async function loadPrincipalKeypair(): Promise<StoredKeypair | null> {
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const request = store.get(PRINCIPAL_KEY_ID);
  return new Promise((resolve, reject) => {
    request.onsuccess = () => {
      db.close();
      resolve(request.result ?? null);
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/** Check if a principal keypair exists in IndexedDB. */
export async function hasPrincipalKeypair(): Promise<boolean> {
  const kp = await loadPrincipalKeypair();
  return kp !== null;
}

/** Delete the stored principal keypair. Irreversible. */
export async function deletePrincipalKeypair(): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  store.delete(PRINCIPAL_KEY_ID);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };
  });
}

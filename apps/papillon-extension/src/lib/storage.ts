/**
 * Encrypted key storage for principal keypairs.
 *
 * AES-256-GCM encryption via Web Crypto API. The encryption key is derived
 * from PBKDF2 using a device-unique random secret + per-key salt.
 *
 * The device secret is generated once on first use and stored separately
 * from the encrypted keys. This ensures encryption can't be broken from
 * just the extension ID (which is public).
 *
 * Session keypairs are NEVER stored — they live in memory only.
 */

import type { EncryptedKeyData } from "./types.js";

const STORAGE_KEY = "pap_principal_key";
const DEVICE_SECRET_KEY = "pap_device_secret";
const PBKDF2_ITERATIONS = 100_000;

/** Get or create a device-unique secret for PBKDF2 key material. */
async function getDeviceSecret(): Promise<Uint8Array> {
  const result = await chrome.storage.local.get(DEVICE_SECRET_KEY);
  if (result[DEVICE_SECRET_KEY]) {
    return new Uint8Array(result[DEVICE_SECRET_KEY]);
  }

  // First run: generate 32 bytes of random entropy
  const secret = crypto.getRandomValues(new Uint8Array(32));
  await chrome.storage.local.set({
    [DEVICE_SECRET_KEY]: Array.from(secret),
  });
  return secret;
}

async function deriveKey(salt: Uint8Array): Promise<CryptoKey> {
  const deviceSecret = await getDeviceSecret();

  // Combine device secret + extension ID for key material
  const idBytes = new TextEncoder().encode(chrome.runtime.id);
  const material = new Uint8Array(deviceSecret.length + idBytes.length);
  material.set(deviceSecret);
  material.set(idBytes, deviceSecret.length);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    material as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Store a principal keypair's secret bytes (32-byte Ed25519 seed). */
export async function storePrincipalKey(
  secretBytes: Uint8Array
): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    secretBytes as BufferSource
  );

  const data: EncryptedKeyData = {
    ciphertext: Array.from(new Uint8Array(ciphertext)),
    salt: Array.from(salt),
    iv: Array.from(iv),
  };

  await chrome.storage.local.set({ [STORAGE_KEY]: data });
}

/** Load and decrypt the stored principal keypair secret bytes. Returns null if none stored. */
export async function loadPrincipalKey(): Promise<Uint8Array | null> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const data = result[STORAGE_KEY] as EncryptedKeyData | undefined;
  if (!data) return null;

  const salt = new Uint8Array(data.salt);
  const iv = new Uint8Array(data.iv);
  const ciphertext = new Uint8Array(data.ciphertext);
  const key = await deriveKey(salt);

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    ciphertext as BufferSource
  );

  return new Uint8Array(plaintext);
}

/** Check if a principal key exists without decrypting it. */
export async function hasPrincipalKey(): Promise<boolean> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return result[STORAGE_KEY] != null;
}

/** Delete the stored principal key. Irreversible. */
export async function deletePrincipalKey(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}

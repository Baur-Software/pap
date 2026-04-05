/**
 * SubtleCrypto Ed25519 key management and signing.
 *
 * Replaces WASM-based Ed25519 signing with browser-native SubtleCrypto.
 * Keys are stored as opaque CryptoKey objects — the private key material
 * never enters JavaScript or WASM linear memory.
 *
 * Browser support: Chrome 113+, Firefox 131+, Safari 17+.
 */

// Ed25519 SPKI header: 12 bytes preceding the 32-byte public key.
// DER: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { <32 bytes> } }
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

// Ed25519 PKCS#8 header: 16 bytes preceding the 32-byte seed.
// DER: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { <32 bytes> } } }
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

let _cachedSupport: boolean | null = null;

/** Feature detection: does SubtleCrypto support Ed25519? */
export async function supportsEd25519(): Promise<boolean> {
  if (_cachedSupport !== null) return _cachedSupport;
  try {
    const kp = await crypto.subtle.generateKey("Ed25519", false, [
      "sign",
      "verify",
    ]);
    // Verify signing actually works (some implementations may accept
    // the algorithm but fail at sign-time)
    const testSig = await crypto.subtle.sign(
      "Ed25519",
      kp.privateKey,
      new Uint8Array([1, 2, 3])
    );
    _cachedSupport = testSig.byteLength === 64;
  } catch {
    _cachedSupport = false;
  }
  return _cachedSupport;
}

/**
 * Generate a new Ed25519 keypair.
 * Private key is NON-extractable (opaque CryptoKey object).
 * Public key IS extractable (needed for DID derivation).
 */
export async function generateKeypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
}

/**
 * Import a 32-byte Ed25519 seed into a non-extractable CryptoKeyPair.
 * Used for migrating existing AES-256-GCM encrypted seeds to SubtleCrypto.
 *
 * The seed is wrapped in a PKCS#8 DER envelope for import.
 * After import, the raw seed can be discarded — the CryptoKey is opaque.
 *
 * @param seed           - 32-byte Ed25519 seed (private scalar input).
 * @param publicKeyBytes - 32-byte Ed25519 public key corresponding to the seed.
 *                         Must be derived by the caller (e.g. via WASM) before
 *                         calling this function so the private key is never
 *                         imported as extractable.
 */
export async function importSeed(
  seed: Uint8Array,
  publicKeyBytes: Uint8Array
): Promise<CryptoKeyPair> {
  if (seed.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  if (publicKeyBytes.length !== 32) {
    throw new Error(
      `Ed25519 public key must be 32 bytes, got ${publicKeyBytes.length}`
    );
  }

  // Build PKCS#8 DER encoding and import private key as NON-extractable.
  // Private key material must not re-enter the JS heap after this point.
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    "Ed25519",
    false, // NOT extractable — private key material stays opaque
    ["sign"]
  );

  // Build SPKI DER encoding and import the public key from the caller-supplied bytes.
  // The public key is derived externally (e.g. via WASM ed25519-dalek) so we
  // never need to export the private key to obtain it.
  const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + 32);
  spki.set(ED25519_SPKI_PREFIX);
  spki.set(publicKeyBytes, ED25519_SPKI_PREFIX.length);

  const publicKey = await crypto.subtle.importKey(
    "spki",
    spki,
    "Ed25519",
    true,
    ["verify"]
  );

  return { privateKey, publicKey };
}

/** Export the raw 32-byte Ed25519 public key from a CryptoKey. */
export async function exportPublicKeyRaw(
  publicKey: CryptoKey
): Promise<Uint8Array> {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const spkiBytes = new Uint8Array(spki);
  // Ed25519 SPKI is always 44 bytes: 12-byte header + 32-byte key
  if (spkiBytes.length !== 44) {
    throw new Error(`Unexpected SPKI length: ${spkiBytes.length}`);
  }
  return spkiBytes.slice(12);
}

/** Sign bytes with an Ed25519 CryptoKey. Returns 64-byte signature. */
export async function sign(
  privateKey: CryptoKey,
  data: Uint8Array
): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, data as BufferSource);
  return new Uint8Array(sig);
}

/** Verify an Ed25519 signature. */
export async function verify(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  return crypto.subtle.verify("Ed25519", publicKey, signature as BufferSource, data as BufferSource);
}

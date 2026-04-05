import { base64urlEncode, base64urlDecode, sha256Hash, sha256, canonicalJson } from './encoding.js';
import { VerificationFailed } from './error.js';
import * as ed from '@noble/ed25519';

/** A single disclosure triple: salt + key + value. */
export interface Disclosure {
  salt: string;
  key: string;
  value: unknown;
}

/** Compute the hash of a disclosure triple. */
function disclosureHash(d: Disclosure): string {
  const bytes = canonicalJson({ salt: d.salt, key: d.key, value: d.value });
  return sha256Hash(bytes);
}

/** Generate a UUID v4 string (crypto-random). */
function uuid(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * SD-JWT: Selective Disclosure JSON Web Token.
 * Holds claims with per-claim salts. The issuer signs a commitment
 * over all claim hashes; selective disclosure reveals only chosen claims.
 */
export class SdJwt {
  readonly issuer: string;
  private readonly claims: Record<string, unknown>;
  private readonly salts: Record<string, string>;
  signature: string | null = null;

  constructor(issuer: string, claims: Record<string, unknown>) {
    this.issuer = issuer;
    this.claims = { ...claims };
    this.salts = {};
    for (const key of Object.keys(claims)) {
      this.salts[key] = uuid();
    }
  }

  /** All claim keys in this SD-JWT. */
  claimKeys(): string[] {
    return Object.keys(this.claims);
  }

  /** Compute hashes for all (salt, key, value) triples. */
  private disclosureHashes(): string[] {
    return Object.keys(this.claims).map((key) =>
      disclosureHash({
        salt: this.salts[key],
        key,
        value: this.claims[key],
      }),
    );
  }

  /** Commitment bytes: sorted disclosure hashes + issuer, serialized to JSON. */
  private commitmentBytes(): Uint8Array {
    const hashes = this.disclosureHashes().sort();
    return canonicalJson({
      issuer: this.issuer,
      disclosure_hashes: hashes,
    });
  }

  /** The sorted disclosure hashes (for external verification). */
  getDisclosureHashes(): string[] {
    return this.disclosureHashes().sort();
  }

  /** Sign the commitment with an Ed25519 keypair. */
  async sign(keypair: { sign(msg: Uint8Array): Promise<Uint8Array> }): Promise<void> {
    const sig = await keypair.sign(this.commitmentBytes());
    this.signature = base64urlEncode(sig);
  }

  /** Verify the commitment signature against a public key. */
  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.signature) return false;
    const sigBytes = base64urlDecode(this.signature);
    return ed.verifyAsync(sigBytes, this.commitmentBytes(), publicKey);
  }

  /** Selectively disclose specific claim keys. */
  disclose(keys: string[]): Disclosure[] {
    return keys
      .filter((k) => k in this.claims)
      .map((key) => ({
        salt: this.salts[key],
        key,
        value: this.claims[key],
      }));
  }

  /** Verify that a disclosure's hash is present in the signed hash list. */
  static verifyDisclosure(disclosure: Disclosure, signedHashes: string[]): boolean {
    const hash = disclosureHash(disclosure);
    return signedHashes.includes(hash);
  }
}

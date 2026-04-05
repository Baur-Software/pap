import * as ed from '@noble/ed25519';
import bs58 from 'bs58';

/** Multicodec prefix for Ed25519 public key (0xed01). */
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

/** Convert an Ed25519 public key to a did:key identifier. */
function publicKeyToDid(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(34);
  prefixed.set(ED25519_MULTICODEC);
  prefixed.set(publicKey, 2);
  return `did:key:z${bs58.encode(prefixed)}`;
}

/** Shared Ed25519 keypair implementation. */
class Ed25519Keypair {
  private constructor(
    private readonly privateKey: Uint8Array,
    private readonly publicKey: Uint8Array,
  ) {}

  static async generate(): Promise<Ed25519Keypair> {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    return new Ed25519Keypair(privateKey, publicKey);
  }

  static async fromBytes(secretKey: Uint8Array): Promise<Ed25519Keypair> {
    if (secretKey.length !== 32) {
      throw new Error('Secret key must be 32 bytes');
    }
    const publicKey = await ed.getPublicKeyAsync(secretKey);
    return new Ed25519Keypair(new Uint8Array(secretKey), publicKey);
  }

  did(): string {
    return publicKeyToDid(this.publicKey);
  }

  publicKeyBytes(): Uint8Array {
    return new Uint8Array(this.publicKey);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed.signAsync(message, this.privateKey);
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return ed.verifyAsync(signature, message, this.publicKey);
  }
}

/**
 * Principal keypair — root of trust, bound to the human principal.
 * Persistent; backed by device keystore or WebAuthn in production.
 */
export class PrincipalKeypair {
  private constructor(private readonly inner: Ed25519Keypair) {}

  static async generate(): Promise<PrincipalKeypair> {
    return new PrincipalKeypair(await Ed25519Keypair.generate());
  }

  static async fromBytes(secretKey: Uint8Array): Promise<PrincipalKeypair> {
    return new PrincipalKeypair(await Ed25519Keypair.fromBytes(secretKey));
  }

  did(): string {
    return this.inner.did();
  }

  publicKeyBytes(): Uint8Array {
    return this.inner.publicKeyBytes();
  }

  sign(message: Uint8Array): Promise<Uint8Array> {
    return this.inner.sign(message);
  }

  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return this.inner.verify(message, signature);
  }
}

/**
 * Session keypair — ephemeral, single-use per session.
 * Generated fresh for each handshake; discarded at session close.
 * Not linked to or derived from the principal keypair.
 */
export class SessionKeypair {
  private constructor(private readonly inner: Ed25519Keypair) {}

  static async generate(): Promise<SessionKeypair> {
    return new SessionKeypair(await Ed25519Keypair.generate());
  }

  did(): string {
    return this.inner.did();
  }

  publicKeyBytes(): Uint8Array {
    return this.inner.publicKeyBytes();
  }

  sign(message: Uint8Array): Promise<Uint8Array> {
    return this.inner.sign(message);
  }

  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return this.inner.verify(message, signature);
  }
}

/** Common interface for both keypair types. */
export type Keypair = PrincipalKeypair | SessionKeypair;

import { base64urlEncode, base64urlDecode, canonicalJson } from './encoding.js';
import {
  InvalidSessionTransition,
  TokenError,
  TokenTargetMismatch,
  NonceConsumed,
  SessionError,
  VerificationFailed,
} from './error.js';
import { Scope } from './scope.js';
import * as ed from '@noble/ed25519';

export enum SessionState {
  Initiated = 'Initiated',
  Open = 'Open',
  Executed = 'Executed',
  Closed = 'Closed',
}

/** Check if a session state transition is valid. */
export function canTransitionSession(from: SessionState, to: SessionState): boolean {
  switch (from) {
    case SessionState.Initiated:
      return to === SessionState.Open || to === SessionState.Closed;
    case SessionState.Open:
      return to === SessionState.Executed || to === SessionState.Closed;
    case SessionState.Executed:
      return to === SessionState.Closed;
    case SessionState.Closed:
      return false;
  }
}

/** Generate a UUID v4 string. */
function uuid(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Capability token authorizing session establishment. */
export class CapabilityToken {
  id: string;
  target_did: string;
  action: string;
  nonce: string;
  issuer_did: string;
  issued_at: string;
  expires_at: string;
  signature: string | null;

  private constructor(fields: {
    id: string;
    target_did: string;
    action: string;
    nonce: string;
    issuer_did: string;
    issued_at: string;
    expires_at: string;
    signature: string | null;
  }) {
    this.id = fields.id;
    this.target_did = fields.target_did;
    this.action = fields.action;
    this.nonce = fields.nonce;
    this.issuer_did = fields.issuer_did;
    this.issued_at = fields.issued_at;
    this.expires_at = fields.expires_at;
    this.signature = fields.signature;
  }

  /** Mint a new unsigned capability token. */
  static mint(targetDid: string, action: string, issuerDid: string, ttlSeconds: number): CapabilityToken {
    const now = new Date();
    const expires = new Date(now.getTime() + ttlSeconds * 1000);
    return new CapabilityToken({
      id: uuid(),
      target_did: targetDid,
      action,
      nonce: uuid(),
      issuer_did: issuerDid,
      issued_at: now.toISOString(),
      expires_at: expires.toISOString(),
      signature: null,
    });
  }

  /** Canonical bytes for signing (all fields except signature). */
  private canonicalBytes(): Uint8Array {
    return canonicalJson({
      id: this.id,
      target_did: this.target_did,
      action: this.action,
      nonce: this.nonce,
      issuer_did: this.issuer_did,
      issued_at: this.issued_at,
      expires_at: this.expires_at,
    });
  }

  /** Sign the token with an Ed25519 keypair. */
  async sign(keypair: { sign(msg: Uint8Array): Promise<Uint8Array> }): Promise<void> {
    const sig = await keypair.sign(this.canonicalBytes());
    this.signature = base64urlEncode(sig);
  }

  /**
   * Verify the token:
   * 1. target_did matches receiver
   * 2. nonce not consumed
   * 3. not expired
   * 4. signature valid
   */
  async verify(
    targetDid: string,
    issuerPublicKey: Uint8Array,
    consumedNonces: Set<string>,
  ): Promise<void> {
    if (this.target_did !== targetDid) {
      throw new TokenTargetMismatch();
    }
    if (consumedNonces.has(this.nonce)) {
      throw new NonceConsumed();
    }
    if (new Date(this.expires_at) < new Date()) {
      throw new TokenError('Token has expired');
    }
    if (!this.signature) {
      throw new TokenError('Token is unsigned');
    }
    const sigBytes = base64urlDecode(this.signature);
    const valid = await ed.verifyAsync(sigBytes, this.canonicalBytes(), issuerPublicKey);
    if (!valid) {
      throw new VerificationFailed();
    }
  }
}

/** A protocol session between two agents. */
export class Session {
  id: string;
  state: SessionState;
  initiatorSessionDid: string | undefined;
  receiverSessionDid: string | undefined;
  action: string;
  scope: Scope;
  createdAt: string;
  readonly consumedNonces: Set<string>;

  private constructor(fields: {
    id: string;
    state: SessionState;
    action: string;
    scope: Scope;
    createdAt: string;
    consumedNonces: Set<string>;
  }) {
    this.id = fields.id;
    this.state = fields.state;
    this.action = fields.action;
    this.scope = fields.scope;
    this.createdAt = fields.createdAt;
    this.consumedNonces = fields.consumedNonces;
  }

  /**
   * Initiate a session from a verified capability token.
   * Consumes the token's nonce and transitions to Initiated.
   */
  static async initiate(
    token: CapabilityToken,
    receiverDid: string,
    issuerPublicKey: Uint8Array,
    scope: Scope,
  ): Promise<Session> {
    const consumedNonces = new Set<string>();
    await token.verify(receiverDid, issuerPublicKey, consumedNonces);
    consumedNonces.add(token.nonce);

    return new Session({
      id: uuid(),
      state: SessionState.Initiated,
      action: token.action,
      scope,
      createdAt: new Date().toISOString(),
      consumedNonces,
    });
  }

  private transition(next: SessionState): void {
    if (!canTransitionSession(this.state, next)) {
      throw new InvalidSessionTransition(this.state, next);
    }
    this.state = next;
  }

  /** Transition from Initiated to Open (after DID exchange). */
  open(initiatorSessionDid: string, receiverSessionDid: string): void {
    this.transition(SessionState.Open);
    this.initiatorSessionDid = initiatorSessionDid;
    this.receiverSessionDid = receiverSessionDid;
  }

  /** Transition from Open to Executed. */
  execute(): void {
    this.transition(SessionState.Executed);
  }

  /** Transition to Closed (from any non-Closed state). */
  close(): void {
    this.transition(SessionState.Closed);
  }
}

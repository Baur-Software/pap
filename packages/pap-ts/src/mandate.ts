import { base64urlEncode, base64urlDecode, sha256Hash, canonicalJson } from './encoding.js';
import {
  DelegationExceedsScope,
  DelegationExceedsTtl,
  InvalidDecayTransition,
  ChainVerificationFailed,
} from './error.js';
import { Scope, DisclosureSet } from './scope.js';
import * as ed from '@noble/ed25519';

export enum DecayState {
  Active = 'Active',
  Degraded = 'Degraded',
  ReadOnly = 'ReadOnly',
  Suspended = 'Suspended',
}

const DECAY_ORDER: Record<DecayState, number> = {
  [DecayState.Active]: 0,
  [DecayState.Degraded]: 1,
  [DecayState.ReadOnly]: 2,
  [DecayState.Suspended]: 3,
};

/** Check if a decay state transition is valid. */
export function canTransitionDecay(from: DecayState, to: DecayState): boolean {
  // Forward transitions: Active→Degraded→ReadOnly→Suspended
  if (DECAY_ORDER[to] === DECAY_ORDER[from] + 1) return true;
  // Renewal: Degraded→Active, ReadOnly→Active
  if (to === DecayState.Active && (from === DecayState.Degraded || from === DecayState.ReadOnly)) return true;
  return false;
}

export interface PaymentProof {
  type: 'Lightning' | 'Ecash';
  hash: string;
}

export class Mandate {
  principal_did: string;
  agent_did: string;
  issuer_did: string;
  parent_mandate_hash: string | null;
  scope: Scope;
  disclosure_set: DisclosureSet;
  ttl: string;
  decay_state: DecayState;
  issued_at: string;
  payment_proof: PaymentProof | null;
  signature: string | null;

  private constructor(fields: {
    principal_did: string;
    agent_did: string;
    issuer_did: string;
    parent_mandate_hash: string | null;
    scope: Scope;
    disclosure_set: DisclosureSet;
    ttl: string;
    decay_state: DecayState;
    issued_at: string;
    payment_proof: PaymentProof | null;
    signature: string | null;
  }) {
    this.principal_did = fields.principal_did;
    this.agent_did = fields.agent_did;
    this.issuer_did = fields.issuer_did;
    this.parent_mandate_hash = fields.parent_mandate_hash;
    this.scope = fields.scope;
    this.disclosure_set = fields.disclosure_set;
    this.ttl = fields.ttl;
    this.decay_state = fields.decay_state;
    this.issued_at = fields.issued_at;
    this.payment_proof = fields.payment_proof;
    this.signature = fields.signature;
  }

  /** Issue a root mandate (principal_did == issuer_did, no parent). */
  static issueRoot(
    principalDid: string,
    agentDid: string,
    scope: Scope,
    disclosureSet: DisclosureSet,
    ttl: string,
  ): Mandate {
    return new Mandate({
      principal_did: principalDid,
      agent_did: agentDid,
      issuer_did: principalDid,
      parent_mandate_hash: null,
      scope,
      disclosure_set: disclosureSet,
      ttl,
      decay_state: DecayState.Active,
      issued_at: new Date().toISOString(),
      payment_proof: null,
      signature: null,
    });
  }

  /** Delegate to a child agent with narrower scope/TTL. */
  delegate(
    agentDid: string,
    scope: Scope,
    disclosureSet: DisclosureSet,
    ttl: string,
  ): Mandate {
    if (!this.scope.contains(scope)) {
      throw new DelegationExceedsScope();
    }
    if (new Date(ttl) > new Date(this.ttl)) {
      throw new DelegationExceedsTtl();
    }
    return new Mandate({
      principal_did: this.principal_did,
      agent_did: agentDid,
      issuer_did: this.agent_did,
      parent_mandate_hash: this.hash(),
      scope,
      disclosure_set: disclosureSet,
      ttl,
      decay_state: DecayState.Active,
      issued_at: new Date().toISOString(),
      payment_proof: null,
      signature: null,
    });
  }

  /** Canonical bytes for signing/hashing (excludes signature and decay_state). */
  private canonicalBytes(): Uint8Array {
    return canonicalJson({
      principal_did: this.principal_did,
      agent_did: this.agent_did,
      issuer_did: this.issuer_did,
      parent_mandate_hash: this.parent_mandate_hash,
      scope: this.scope,
      disclosure_set: this.disclosure_set,
      ttl: this.ttl,
      issued_at: this.issued_at,
      payment_proof: this.payment_proof,
    });
  }

  /** SHA-256 hash of canonical form, base64url-no-pad encoded. */
  hash(): string {
    return sha256Hash(this.canonicalBytes());
  }

  /** Sign the mandate with an Ed25519 keypair. */
  async sign(keypair: { sign(msg: Uint8Array): Promise<Uint8Array> }): Promise<void> {
    const sig = await keypair.sign(this.canonicalBytes());
    this.signature = base64urlEncode(sig);
  }

  /** Verify the signature against a public key (32 bytes). */
  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.signature) return false;
    const sigBytes = base64urlDecode(this.signature);
    return ed.verifyAsync(sigBytes, this.canonicalBytes(), publicKey);
  }

  /** Check if the mandate has expired (TTL in the past). */
  isExpired(): boolean {
    return new Date(this.ttl) < new Date();
  }

  /** Compute current decay state based on time and decay window. */
  computeDecayState(decayWindowSecs: number): DecayState {
    const now = Date.now();
    const ttlMs = new Date(this.ttl).getTime();
    if (now > ttlMs) return DecayState.ReadOnly;
    const remainingMs = ttlMs - now;
    if (remainingMs <= decayWindowSecs * 1000) return DecayState.Degraded;
    return DecayState.Active;
  }

  /** Transition to a new decay state (validates the transition). */
  transitionDecay(next: DecayState): void {
    if (!canTransitionDecay(this.decay_state, next)) {
      throw new InvalidDecayTransition(this.decay_state, next);
    }
    this.decay_state = next;
  }

  /** Attach a payment proof. */
  withPaymentProof(proof: PaymentProof): Mandate {
    this.payment_proof = proof;
    return this;
  }
}

/** A chain of mandates from root to leaf. */
export class MandateChain {
  readonly mandates: Mandate[];

  constructor(root: Mandate) {
    this.mandates = [root];
  }

  push(mandate: Mandate): void {
    this.mandates.push(mandate);
  }

  leaf(): Mandate {
    return this.mandates[this.mandates.length - 1];
  }

  root(): Mandate {
    return this.mandates[0];
  }

  /**
   * Verify the entire chain:
   * 1. Root must have no parent hash and issuer == principal
   * 2. Each child's parent_mandate_hash == hash of previous
   * 3. Each child's scope contained by parent's scope
   * 4. Each child's TTL does not exceed parent's TTL
   * 5. Signatures verify against the appropriate keys
   */
  async verifyChain(keys: Uint8Array[]): Promise<void> {
    if (this.mandates.length === 0) {
      throw new ChainVerificationFailed('Chain is empty');
    }
    if (keys.length !== this.mandates.length) {
      throw new ChainVerificationFailed('Key count does not match mandate count');
    }

    const root = this.mandates[0];
    if (root.parent_mandate_hash !== null) {
      throw new ChainVerificationFailed('Root mandate must have no parent hash');
    }
    if (root.issuer_did !== root.principal_did) {
      throw new ChainVerificationFailed('Root mandate issuer must equal principal');
    }

    // Verify root signature
    const rootValid = await root.verify(keys[0]);
    if (!rootValid) {
      throw new ChainVerificationFailed('Root mandate signature invalid');
    }

    for (let i = 1; i < this.mandates.length; i++) {
      const parent = this.mandates[i - 1];
      const child = this.mandates[i];

      if (child.parent_mandate_hash !== parent.hash()) {
        throw new ChainVerificationFailed(`Mandate ${i}: parent hash mismatch`);
      }
      if (!parent.scope.contains(child.scope)) {
        throw new ChainVerificationFailed(`Mandate ${i}: scope exceeds parent`);
      }
      if (new Date(child.ttl) > new Date(parent.ttl)) {
        throw new ChainVerificationFailed(`Mandate ${i}: TTL exceeds parent`);
      }
      if (child.principal_did !== parent.principal_did) {
        throw new ChainVerificationFailed(`Mandate ${i}: principal DID mismatch`);
      }
      if (child.issuer_did !== parent.agent_did) {
        throw new ChainVerificationFailed(`Mandate ${i}: issuer must be parent's agent`);
      }

      const valid = await child.verify(keys[i]);
      if (!valid) {
        throw new ChainVerificationFailed(`Mandate ${i}: signature invalid`);
      }
    }
  }
}

import { base64urlEncode, base64urlDecode, canonicalJson } from './encoding.js';
import { ReceiptError, VerificationFailed } from './error.js';
import { Session, SessionState } from './session.js';
import * as ed from '@noble/ed25519';

export enum SessionOutcome {
  Fulfilled = 'fulfilled',
  Partial = 'partial',
  Failed = 'failed',
  Disputed = 'disputed',
}

/** Session attestation — one party's view of the session outcome. */
export class SessionAttestation {
  session_id: string;
  attester_did: string;
  outcome: SessionOutcome;
  action_type: string;
  timestamp: string;
  signature: string | null;

  constructor(
    sessionId: string,
    attesterDid: string,
    outcome: SessionOutcome,
    actionType: string,
  ) {
    this.session_id = sessionId;
    this.attester_did = attesterDid;
    this.outcome = outcome;
    this.action_type = actionType;
    this.timestamp = new Date().toISOString();
    this.signature = null;
  }

  private canonicalBytes(): Uint8Array {
    return canonicalJson({
      session_id: this.session_id,
      attester_did: this.attester_did,
      outcome: this.outcome,
      action_type: this.action_type,
      timestamp: this.timestamp,
    });
  }

  async sign(keypair: { sign(msg: Uint8Array): Promise<Uint8Array> }): Promise<void> {
    const sig = await keypair.sign(this.canonicalBytes());
    this.signature = base64urlEncode(sig);
  }

  async verify(publicKey: Uint8Array): Promise<boolean> {
    if (!this.signature) return false;
    const sigBytes = base64urlDecode(this.signature);
    return ed.verifyAsync(sigBytes, this.canonicalBytes(), publicKey);
  }
}

/**
 * Transaction receipt — co-signed record of a session's execution.
 * Contains property references only, never values (spec invariant).
 */
export class TransactionReceipt {
  session_id: string;
  action: string;
  initiating_agent_did: string;
  receiving_agent_did: string;
  disclosed_by_initiator: string[];
  disclosed_by_receiver: string[];
  executed: string;
  returned: string;
  payment_proof_commitment: string | null;
  timestamp: string;
  signatures: string[];
  attestations: SessionAttestation[];

  private constructor(fields: {
    session_id: string;
    action: string;
    initiating_agent_did: string;
    receiving_agent_did: string;
    disclosed_by_initiator: string[];
    disclosed_by_receiver: string[];
    executed: string;
    returned: string;
    payment_proof_commitment: string | null;
    timestamp: string;
  }) {
    this.session_id = fields.session_id;
    this.action = fields.action;
    this.initiating_agent_did = fields.initiating_agent_did;
    this.receiving_agent_did = fields.receiving_agent_did;
    this.disclosed_by_initiator = fields.disclosed_by_initiator;
    this.disclosed_by_receiver = fields.disclosed_by_receiver;
    this.executed = fields.executed;
    this.returned = fields.returned;
    this.payment_proof_commitment = fields.payment_proof_commitment;
    this.timestamp = fields.timestamp;
    this.signatures = [];
    this.attestations = [];
  }

  /** Create a receipt from an executed session. */
  static fromSession(
    session: Session,
    disclosedByInitiator: string[],
    disclosedByReceiver: string[],
    executed: string,
    returned: string,
  ): TransactionReceipt {
    if (!session.initiatorSessionDid || !session.receiverSessionDid) {
      throw new ReceiptError('Session must have both session DIDs set');
    }
    return new TransactionReceipt({
      session_id: session.id,
      action: session.action,
      initiating_agent_did: session.initiatorSessionDid,
      receiving_agent_did: session.receiverSessionDid,
      disclosed_by_initiator: disclosedByInitiator,
      disclosed_by_receiver: disclosedByReceiver,
      executed,
      returned,
      payment_proof_commitment: null,
      timestamp: new Date().toISOString(),
    });
  }

  /** Canonical bytes for signing (all fields except signatures and attestations). */
  private canonicalBytes(): Uint8Array {
    return canonicalJson({
      session_id: this.session_id,
      action: this.action,
      initiating_agent_did: this.initiating_agent_did,
      receiving_agent_did: this.receiving_agent_did,
      disclosed_by_initiator: this.disclosed_by_initiator,
      disclosed_by_receiver: this.disclosed_by_receiver,
      executed: this.executed,
      returned: this.returned,
      payment_proof_commitment: this.payment_proof_commitment,
      timestamp: this.timestamp,
    });
  }

  /** Co-sign the receipt (appends signature to signatures array). */
  async coSign(keypair: { sign(msg: Uint8Array): Promise<Uint8Array> }): Promise<void> {
    const sig = await keypair.sign(this.canonicalBytes());
    this.signatures.push(base64urlEncode(sig));
  }

  /** Verify a specific signature by index against a public key. */
  async verifySignature(index: number, publicKey: Uint8Array): Promise<boolean> {
    if (index < 0 || index >= this.signatures.length) return false;
    const sigBytes = base64urlDecode(this.signatures[index]);
    return ed.verifyAsync(sigBytes, this.canonicalBytes(), publicKey);
  }

  /** Add a session attestation. */
  addAttestation(attestation: SessionAttestation): void {
    this.attestations.push(attestation);
  }

  /** Set payment proof commitment (hash only, never amounts/destinations). */
  withPaymentProofCommitment(commitment: string): TransactionReceipt {
    this.payment_proof_commitment = commitment;
    return this;
  }
}

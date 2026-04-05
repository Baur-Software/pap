import { sha256, canonicalJson, base64urlEncode, base64urlDecode, utf8Encode } from './encoding.js';
import { CapabilityToken, Session, SessionState } from './session.js';
import { TransactionReceipt } from './receipt.js';
import { SessionKeypair } from './keypair.js';
import type { Disclosure } from './credential.js';
import * as ed from '@noble/ed25519';

// --- Protocol Message Types (discriminated union) ---

export type ProtocolMessage =
  | { type: 'TokenPresentation'; token: CapabilityToken }
  | { type: 'TokenAccepted'; session_id: string; receiver_session_did: string }
  | { type: 'TokenRejected'; reason: string }
  | { type: 'SessionDidExchange'; initiator_session_did: string }
  | { type: 'SessionDidAck' }
  | { type: 'DisclosureOffer'; disclosures: Disclosure[] }
  | { type: 'DisclosureAccepted' }
  | { type: 'ExecutionResult'; result: unknown }
  | { type: 'ReceiptForCoSign'; receipt: TransactionReceipt }
  | { type: 'ReceiptCoSigned'; receipt: TransactionReceipt }
  | { type: 'SessionClose'; session_id: string }
  | { type: 'SessionClosed' }
  | { type: 'Error'; code: string; message: string };

// --- Envelope ---

export interface Envelope {
  id: string;
  session_id: string;
  sender: string;
  recipient: string;
  sequence: number;
  payload: ProtocolMessage;
  timestamp: string;
  signature: string | null;
}

/** Generate a UUID v4. */
function uuid(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Create a new envelope. */
export function createEnvelope(
  sessionId: string,
  sender: string,
  recipient: string,
  sequence: number,
  payload: ProtocolMessage,
): Envelope {
  return {
    id: uuid(),
    session_id: sessionId,
    sender,
    recipient,
    sequence,
    payload,
    timestamp: new Date().toISOString(),
    signature: null,
  };
}

/**
 * Compute signable bytes for an envelope:
 * SHA-256(session_id_bytes || sequence_big_endian_8_bytes || payload_json_bytes)
 */
export function envelopeSignableBytes(envelope: Envelope): Uint8Array {
  const sessionIdBytes = utf8Encode(envelope.session_id);
  const sequenceBytes = new Uint8Array(8);
  const view = new DataView(sequenceBytes.buffer);
  view.setBigUint64(0, BigInt(envelope.sequence), false); // big-endian
  const payloadBytes = canonicalJson(envelope.payload);

  const combined = new Uint8Array(sessionIdBytes.length + 8 + payloadBytes.length);
  combined.set(sessionIdBytes, 0);
  combined.set(sequenceBytes, sessionIdBytes.length);
  combined.set(payloadBytes, sessionIdBytes.length + 8);

  return sha256(combined);
}

/** Sign an envelope with an ephemeral session keypair. */
export async function signEnvelope(
  envelope: Envelope,
  keypair: { sign(msg: Uint8Array): Promise<Uint8Array> },
): Promise<Envelope> {
  const signable = envelopeSignableBytes(envelope);
  const sig = await keypair.sign(signable);
  return { ...envelope, signature: base64urlEncode(sig) };
}

/** Verify an envelope's signature against a session public key. */
export async function verifyEnvelope(
  envelope: Envelope,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (!envelope.signature) return false;
  const sigBytes = base64urlDecode(envelope.signature);
  const signable = envelopeSignableBytes(envelope);
  return ed.verifyAsync(sigBytes, signable, publicKey);
}

// --- HTTP Handshake Client ---

/**
 * Fetch-based 6-phase handshake client.
 * Executes the full PAP protocol against an HTTP endpoint.
 */
export class HandshakeClient {
  constructor(private readonly baseUrl: string) {}

  async executeHandshake(
    token: CapabilityToken,
    sessionKeypair: SessionKeypair,
    disclosures: Disclosure[] = [],
  ): Promise<{ receipt: TransactionReceipt; result: unknown }> {
    const base = this.baseUrl.replace(/\/$/, '');

    const post = async (url: string, body?: unknown): Promise<Response> => {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        ...(body != null ? { body: JSON.stringify(body) } : {}),
      });
      if (!resp.ok) {
        throw new Error(`PAP handshake failed at ${url}: HTTP ${resp.status}`);
      }
      return resp;
    };

    // Phase 1: Token Presentation
    const phase1 = await post(`${base}/session`, { type: 'TokenPresentation', token });
    const phase1Body = await phase1.json();
    if (phase1Body.type === 'TokenRejected') {
      throw new Error(`Token rejected: ${phase1Body.reason}`);
    }
    const { session_id, receiver_session_did } = phase1Body;

    // Phase 2: Ephemeral DID Exchange
    await post(`${base}/session/${session_id}/did`, {
      type: 'SessionDidExchange',
      initiator_session_did: sessionKeypair.did(),
    });

    // Phase 3: Disclosure
    await post(`${base}/session/${session_id}/disclosure`, {
      type: 'DisclosureOffer',
      disclosures,
    });

    // Phase 4: Execution
    const phase4 = await post(`${base}/session/${session_id}/execute`);
    const executionResult = await phase4.json();

    // Phase 5: Receipt Co-Signing
    const phase5 = await post(`${base}/session/${session_id}/receipt`, {
      type: 'ReceiptForCoSign',
      receipt: executionResult.receipt,
    });
    const phase5Body = await phase5.json();
    const receipt = phase5Body.receipt as TransactionReceipt;

    // Phase 6: Session Close
    await post(`${base}/session/${session_id}/close`, {
      type: 'SessionClose',
      session_id,
    });

    return { receipt, result: executionResult.result };
  }
}

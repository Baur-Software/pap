import { describe, it, expect } from 'vitest';
import { createEnvelope, envelopeSignableBytes, signEnvelope, verifyEnvelope } from '../src/transport.js';
import { SessionKeypair } from '../src/keypair.js';

describe('Envelope', () => {
  it('creates with correct fields', () => {
    const env = createEnvelope(
      'session-123',
      'did:key:zSender',
      'did:key:zRecipient',
      1,
      { type: 'SessionDidAck' },
    );
    expect(env.id).toBeTruthy();
    expect(env.session_id).toBe('session-123');
    expect(env.sender).toBe('did:key:zSender');
    expect(env.sequence).toBe(1);
    expect(env.signature).toBeNull();
  });

  it('signable bytes are deterministic', () => {
    const env = createEnvelope('s1', 'a', 'b', 0, { type: 'SessionDidAck' });
    const a = envelopeSignableBytes(env);
    const b = envelopeSignableBytes(env);
    expect(a).toEqual(b);
    expect(a.length).toBe(32); // SHA-256 output
  });

  it('signable bytes change with sequence', () => {
    const env1 = createEnvelope('s1', 'a', 'b', 0, { type: 'SessionDidAck' });
    const env2 = createEnvelope('s1', 'a', 'b', 1, { type: 'SessionDidAck' });
    const a = envelopeSignableBytes(env1);
    const b = envelopeSignableBytes(env2);
    expect(a).not.toEqual(b);
  });

  it('signs and verifies', async () => {
    const kp = await SessionKeypair.generate();
    const env = createEnvelope('s1', kp.did(), 'did:key:zR', 0, { type: 'SessionDidAck' });
    const signed = await signEnvelope(env, kp);
    expect(signed.signature).toBeTruthy();
    expect(await verifyEnvelope(signed, kp.publicKeyBytes())).toBe(true);
  });

  it('verification fails with wrong key', async () => {
    const kp1 = await SessionKeypair.generate();
    const kp2 = await SessionKeypair.generate();
    const env = createEnvelope('s1', kp1.did(), 'did:key:zR', 0, { type: 'SessionDidAck' });
    const signed = await signEnvelope(env, kp1);
    expect(await verifyEnvelope(signed, kp2.publicKeyBytes())).toBe(false);
  });

  it('unsigned envelope fails verification', async () => {
    const kp = await SessionKeypair.generate();
    const env = createEnvelope('s1', kp.did(), 'did:key:zR', 0, { type: 'SessionDidAck' });
    expect(await verifyEnvelope(env, kp.publicKeyBytes())).toBe(false);
  });
});

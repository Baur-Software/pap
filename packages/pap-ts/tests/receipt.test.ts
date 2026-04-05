import { describe, it, expect } from 'vitest';
import { PrincipalKeypair, SessionKeypair } from '../src/keypair.js';
import { Scope } from '../src/scope.js';
import { CapabilityToken, Session, SessionState } from '../src/session.js';
import {
  TransactionReceipt,
  SessionAttestation,
  SessionOutcome,
} from '../src/receipt.js';
import { ReceiptError } from '../src/error.js';

const searchAction = { action: 'schema:SearchAction', conditions: {} };

async function createExecutedSession() {
  const issuer = await PrincipalKeypair.generate();
  const initKp = await SessionKeypair.generate();
  const recvKp = await SessionKeypair.generate();
  const scope = new Scope([searchAction]);

  const token = CapabilityToken.mint(
    'did:key:zReceiver',
    'schema:SearchAction',
    issuer.did(),
    300,
  );
  await token.sign(issuer);

  const session = await Session.initiate(
    token,
    'did:key:zReceiver',
    issuer.publicKeyBytes(),
    scope,
  );
  session.open(initKp.did(), recvKp.did());
  session.execute();

  return { session, initKp, recvKp };
}

describe('TransactionReceipt', () => {
  it('creates from an executed session', async () => {
    const { session } = await createExecutedSession();

    const receipt = TransactionReceipt.fromSession(
      session,
      ['schema:Person.schema:name'],
      ['schema:Flight.schema:flightNumber'],
      'Searched for flights',
      'Found 3 matching flights',
    );

    expect(receipt.session_id).toBe(session.id);
    expect(receipt.action).toBe('schema:SearchAction');
    expect(receipt.disclosed_by_initiator).toEqual(['schema:Person.schema:name']);
    expect(receipt.disclosed_by_receiver).toEqual(['schema:Flight.schema:flightNumber']);
    expect(receipt.signatures).toHaveLength(0);
  });

  it('co-signs and verifies with both session keys', async () => {
    const { session, initKp, recvKp } = await createExecutedSession();

    const receipt = TransactionReceipt.fromSession(
      session,
      ['schema:Person.schema:name'],
      ['schema:Flight.schema:flightNumber'],
      'Searched for flights',
      'Found 3 matching flights',
    );

    // Both parties co-sign
    await receipt.coSign(initKp);
    await receipt.coSign(recvKp);
    expect(receipt.signatures).toHaveLength(2);

    // Verify each signature
    expect(await receipt.verifySignature(0, initKp.publicKeyBytes())).toBe(true);
    expect(await receipt.verifySignature(1, recvKp.publicKeyBytes())).toBe(true);

    // Cross-verify fails
    expect(await receipt.verifySignature(0, recvKp.publicKeyBytes())).toBe(false);
    expect(await receipt.verifySignature(1, initKp.publicKeyBytes())).toBe(false);
  });

  it('verifySignature returns false for out-of-bounds index', async () => {
    const { session, initKp } = await createExecutedSession();
    const receipt = TransactionReceipt.fromSession(
      session,
      [],
      [],
      'test',
      'test',
    );
    await receipt.coSign(initKp);
    expect(await receipt.verifySignature(5, initKp.publicKeyBytes())).toBe(false);
    expect(await receipt.verifySignature(-1, initKp.publicKeyBytes())).toBe(false);
  });

  it('rejects session without session DIDs', async () => {
    const issuer = await PrincipalKeypair.generate();
    const scope = new Scope([searchAction]);
    const token = CapabilityToken.mint(
      'did:key:zReceiver',
      'schema:SearchAction',
      issuer.did(),
      300,
    );
    await token.sign(issuer);

    const session = await Session.initiate(
      token,
      'did:key:zReceiver',
      issuer.publicKeyBytes(),
      scope,
    );
    // Session is Initiated but not Open — no session DIDs set

    expect(() =>
      TransactionReceipt.fromSession(session, [], [], 'test', 'test'),
    ).toThrow(ReceiptError);
  });

  it('withPaymentProofCommitment sets commitment', async () => {
    const { session } = await createExecutedSession();
    const receipt = TransactionReceipt.fromSession(session, [], [], 'test', 'test');
    expect(receipt.payment_proof_commitment).toBeNull();

    const result = receipt.withPaymentProofCommitment('sha256-abc');
    expect(result).toBe(receipt);
    expect(receipt.payment_proof_commitment).toBe('sha256-abc');
  });

  it('contains property references only (spec invariant)', async () => {
    const { session } = await createExecutedSession();

    const receipt = TransactionReceipt.fromSession(
      session,
      ['schema:Person.schema:name'], // reference, not "John Doe"
      ['schema:Flight.schema:price'], // reference, not "$299"
      'Booked flight',
      'Booking confirmed',
    );

    // The disclosed_by fields contain property references, never values
    for (const ref of receipt.disclosed_by_initiator) {
      expect(ref).toMatch(/^schema:\w+\.schema:\w+$/);
    }
    for (const ref of receipt.disclosed_by_receiver) {
      expect(ref).toMatch(/^schema:\w+\.schema:\w+$/);
    }
  });
});

describe('SessionAttestation', () => {
  it('signs and verifies', async () => {
    const kp = await SessionKeypair.generate();
    const att = new SessionAttestation(
      'session-123',
      kp.did(),
      SessionOutcome.Fulfilled,
      'schema:SearchAction',
    );

    await att.sign(kp);
    expect(att.signature).toBeTruthy();
    expect(await att.verify(kp.publicKeyBytes())).toBe(true);
  });

  it('verification fails with wrong key', async () => {
    const kp1 = await SessionKeypair.generate();
    const kp2 = await SessionKeypair.generate();
    const att = new SessionAttestation(
      'session-123',
      kp1.did(),
      SessionOutcome.Failed,
      'schema:SearchAction',
    );

    await att.sign(kp1);
    expect(await att.verify(kp2.publicKeyBytes())).toBe(false);
  });

  it('receipt tracks attestation status', async () => {
    const { session, initKp, recvKp } = await createExecutedSession();

    const receipt = TransactionReceipt.fromSession(
      session,
      [],
      [],
      'test',
      'test',
    );

    // No attestations initially
    expect(receipt.attestations).toHaveLength(0);

    // Add one attestation
    const att1 = new SessionAttestation(
      session.id,
      initKp.did(),
      SessionOutcome.Fulfilled,
      'schema:SearchAction',
    );
    await att1.sign(initKp);
    receipt.addAttestation(att1);
    expect(receipt.attestations).toHaveLength(1);

    // Add second attestation
    const att2 = new SessionAttestation(
      session.id,
      recvKp.did(),
      SessionOutcome.Fulfilled,
      'schema:SearchAction',
    );
    await att2.sign(recvKp);
    receipt.addAttestation(att2);
    expect(receipt.attestations).toHaveLength(2);
  });
});

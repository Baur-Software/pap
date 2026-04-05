import { describe, it, expect } from 'vitest';
import { PrincipalKeypair, SessionKeypair } from '../src/keypair.js';
import { Scope } from '../src/scope.js';
import {
  SessionState,
  canTransitionSession,
  CapabilityToken,
  Session,
} from '../src/session.js';
import {
  TokenTargetMismatch,
  NonceConsumed,
  VerificationFailed,
  InvalidSessionTransition,
} from '../src/error.js';

const searchAction = { action: 'schema:SearchAction', conditions: {} };

describe('SessionState transitions', () => {
  it('Initiated → Open is valid', () => {
    expect(canTransitionSession(SessionState.Initiated, SessionState.Open)).toBe(true);
  });

  it('Open → Executed is valid', () => {
    expect(canTransitionSession(SessionState.Open, SessionState.Executed)).toBe(true);
  });

  it('Executed → Closed is valid', () => {
    expect(canTransitionSession(SessionState.Executed, SessionState.Closed)).toBe(true);
  });

  it('Initiated → Closed (abort) is valid', () => {
    expect(canTransitionSession(SessionState.Initiated, SessionState.Closed)).toBe(true);
  });

  it('Open → Closed (abort) is valid', () => {
    expect(canTransitionSession(SessionState.Open, SessionState.Closed)).toBe(true);
  });

  it('Closed → anything is invalid', () => {
    expect(canTransitionSession(SessionState.Closed, SessionState.Open)).toBe(false);
    expect(canTransitionSession(SessionState.Closed, SessionState.Initiated)).toBe(false);
  });

  it('Executed → Open (backwards) is invalid', () => {
    expect(canTransitionSession(SessionState.Executed, SessionState.Open)).toBe(false);
  });
});

describe('CapabilityToken', () => {
  it('mints a token with UUID fields', async () => {
    const issuer = await PrincipalKeypair.generate();
    const token = CapabilityToken.mint(
      'did:key:zReceiver',
      'schema:SearchAction',
      issuer.did(),
      300,
    );

    expect(token.id).toMatch(/^[0-9a-f-]+$/);
    expect(token.nonce).toMatch(/^[0-9a-f-]+$/);
    expect(token.target_did).toBe('did:key:zReceiver');
    expect(token.action).toBe('schema:SearchAction');
    expect(token.issuer_did).toBe(issuer.did());
    expect(token.signature).toBeNull();
  });

  it('signs and verifies a token', async () => {
    const issuer = await PrincipalKeypair.generate();
    const token = CapabilityToken.mint(
      'did:key:zReceiver',
      'schema:SearchAction',
      issuer.did(),
      300,
    );

    await token.sign(issuer);
    expect(token.signature).toBeTruthy();

    // Should not throw
    const nonces = new Set<string>();
    await token.verify('did:key:zReceiver', issuer.publicKeyBytes(), nonces);
  });

  it('rejects wrong target DID', async () => {
    const issuer = await PrincipalKeypair.generate();
    const token = CapabilityToken.mint(
      'did:key:zReceiver',
      'schema:SearchAction',
      issuer.did(),
      300,
    );
    await token.sign(issuer);

    await expect(
      token.verify('did:key:zWrongReceiver', issuer.publicKeyBytes(), new Set()),
    ).rejects.toThrow(TokenTargetMismatch);
  });

  it('rejects consumed nonce', async () => {
    const issuer = await PrincipalKeypair.generate();
    const token = CapabilityToken.mint(
      'did:key:zReceiver',
      'schema:SearchAction',
      issuer.did(),
      300,
    );
    await token.sign(issuer);

    const consumed = new Set<string>([token.nonce]);
    await expect(
      token.verify('did:key:zReceiver', issuer.publicKeyBytes(), consumed),
    ).rejects.toThrow(NonceConsumed);
  });

  it('rejects invalid signature', async () => {
    const issuer = await PrincipalKeypair.generate();
    const other = await PrincipalKeypair.generate();
    const token = CapabilityToken.mint(
      'did:key:zReceiver',
      'schema:SearchAction',
      issuer.did(),
      300,
    );
    await token.sign(issuer);

    await expect(
      token.verify('did:key:zReceiver', other.publicKeyBytes(), new Set()),
    ).rejects.toThrow(VerificationFailed);
  });
});

describe('Session', () => {
  it('full lifecycle: initiate → open → execute → close', async () => {
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
    expect(session.state).toBe(SessionState.Initiated);
    expect(session.action).toBe('schema:SearchAction');

    session.open(initKp.did(), recvKp.did());
    expect(session.state).toBe(SessionState.Open);
    expect(session.initiatorSessionDid).toBe(initKp.did());

    session.execute();
    expect(session.state).toBe(SessionState.Executed);

    session.close();
    expect(session.state).toBe(SessionState.Closed);
  });

  it('rejects invalid state transitions', async () => {
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

    // Can't execute from Initiated (must go through Open first)
    expect(() => session.execute()).toThrow(InvalidSessionTransition);
  });

  it('allows abort from Initiated', async () => {
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

    session.close(); // abort
    expect(session.state).toBe(SessionState.Closed);
  });
});

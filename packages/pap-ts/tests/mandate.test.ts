import { describe, it, expect } from 'vitest';
import { PrincipalKeypair } from '../src/keypair.js';
import { Scope, DisclosureSet } from '../src/scope.js';
import {
  DecayState,
  canTransitionDecay,
  Mandate,
  MandateChain,
} from '../src/mandate.js';
import { DelegationExceedsScope, DelegationExceedsTtl, InvalidDecayTransition, ChainVerificationFailed } from '../src/error.js';

const futureDate = (hours: number) =>
  new Date(Date.now() + hours * 3600_000).toISOString();

const searchAction = { action: 'schema:SearchAction', conditions: {} };
const payAction = { action: 'schema:PayAction', conditions: {} };

describe('DecayState transitions', () => {
  it('Active → Degraded is valid', () => {
    expect(canTransitionDecay(DecayState.Active, DecayState.Degraded)).toBe(true);
  });

  it('Degraded → ReadOnly is valid', () => {
    expect(canTransitionDecay(DecayState.Degraded, DecayState.ReadOnly)).toBe(true);
  });

  it('ReadOnly → Suspended is valid', () => {
    expect(canTransitionDecay(DecayState.ReadOnly, DecayState.Suspended)).toBe(true);
  });

  it('Degraded → Active (renewal) is valid', () => {
    expect(canTransitionDecay(DecayState.Degraded, DecayState.Active)).toBe(true);
  });

  it('ReadOnly → Active (renewal) is valid', () => {
    expect(canTransitionDecay(DecayState.ReadOnly, DecayState.Active)).toBe(true);
  });

  it('Suspended → anything is invalid', () => {
    expect(canTransitionDecay(DecayState.Suspended, DecayState.Active)).toBe(false);
    expect(canTransitionDecay(DecayState.Suspended, DecayState.Degraded)).toBe(false);
  });

  it('Active → ReadOnly (skip) is invalid', () => {
    expect(canTransitionDecay(DecayState.Active, DecayState.ReadOnly)).toBe(false);
  });
});

describe('Mandate', () => {
  it('issues a root mandate', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent = await PrincipalKeypair.generate();
    const scope = new Scope([searchAction]);

    const mandate = Mandate.issueRoot(
      principal.did(),
      agent.did(),
      scope,
      DisclosureSet.empty(),
      futureDate(1),
    );

    expect(mandate.principal_did).toBe(principal.did());
    expect(mandate.agent_did).toBe(agent.did());
    expect(mandate.issuer_did).toBe(principal.did());
    expect(mandate.parent_mandate_hash).toBeNull();
    expect(mandate.decay_state).toBe(DecayState.Active);
    expect(mandate.signature).toBeNull();
  });

  it('signs and verifies a mandate', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent = await PrincipalKeypair.generate();
    const scope = new Scope([searchAction]);

    const mandate = Mandate.issueRoot(
      principal.did(),
      agent.did(),
      scope,
      DisclosureSet.empty(),
      futureDate(1),
    );

    await mandate.sign(principal);
    expect(mandate.signature).toBeTruthy();
    expect(await mandate.verify(principal.publicKeyBytes())).toBe(true);
  });

  it('verification fails with wrong key', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent = await PrincipalKeypair.generate();
    const other = await PrincipalKeypair.generate();

    const mandate = Mandate.issueRoot(
      principal.did(),
      agent.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );

    await mandate.sign(principal);
    expect(await mandate.verify(other.publicKeyBytes())).toBe(false);
  });

  it('hash is deterministic', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent = await PrincipalKeypair.generate();
    const ttl = futureDate(1);

    const m1 = Mandate.issueRoot(
      principal.did(),
      agent.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      ttl,
    );

    // Hash should be the same when computed multiple times
    expect(m1.hash()).toBe(m1.hash());
  });

  it('delegates with narrower scope', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent1 = await PrincipalKeypair.generate();
    const agent2 = await PrincipalKeypair.generate();
    const ttl = futureDate(2);

    const root = Mandate.issueRoot(
      principal.did(),
      agent1.did(),
      new Scope([searchAction, payAction]),
      DisclosureSet.empty(),
      ttl,
    );

    const child = root.delegate(
      agent2.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );

    expect(child.principal_did).toBe(principal.did());
    expect(child.issuer_did).toBe(agent1.did());
    expect(child.parent_mandate_hash).toBe(root.hash());
  });

  it('rejects delegation that exceeds scope', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent1 = await PrincipalKeypair.generate();
    const agent2 = await PrincipalKeypair.generate();

    const root = Mandate.issueRoot(
      principal.did(),
      agent1.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(2),
    );

    expect(() =>
      root.delegate(
        agent2.did(),
        new Scope([searchAction, payAction]), // exceeds parent
        DisclosureSet.empty(),
        futureDate(1),
      ),
    ).toThrow(DelegationExceedsScope);
  });

  it('rejects delegation that exceeds TTL', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent1 = await PrincipalKeypair.generate();
    const agent2 = await PrincipalKeypair.generate();

    const root = Mandate.issueRoot(
      principal.did(),
      agent1.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );

    expect(() =>
      root.delegate(
        agent2.did(),
        new Scope([searchAction]),
        DisclosureSet.empty(),
        futureDate(5), // exceeds parent TTL
      ),
    ).toThrow(DelegationExceedsTtl);
  });

  it('isExpired returns false for future TTL', () => {
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );
    expect(mandate.isExpired()).toBe(false);
  });

  it('computeDecayState returns Active for far-future TTL', () => {
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(24),
    );
    expect(mandate.computeDecayState(3600)).toBe(DecayState.Active);
  });

  it('computeDecayState returns Degraded within decay window', () => {
    // TTL 30 seconds from now, decay window 60 seconds → within window → Degraded
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      new Date(Date.now() + 30_000).toISOString(),
    );
    expect(mandate.computeDecayState(60)).toBe(DecayState.Degraded);
  });

  it('computeDecayState returns ReadOnly after expiry', () => {
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      new Date(Date.now() - 1000).toISOString(), // expired 1 second ago
    );
    expect(mandate.computeDecayState(3600)).toBe(DecayState.ReadOnly);
  });

  it('isExpired returns true for past TTL', () => {
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      new Date(Date.now() - 1000).toISOString(),
    );
    expect(mandate.isExpired()).toBe(true);
  });

  it('withPaymentProof attaches proof', () => {
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );
    expect(mandate.payment_proof).toBeNull();

    const result = mandate.withPaymentProof({ type: 'Lightning', hash: 'abc123' });
    expect(result).toBe(mandate); // returns self
    expect(mandate.payment_proof).toEqual({ type: 'Lightning', hash: 'abc123' });
  });

  it('verify returns false when unsigned', async () => {
    const principal = await PrincipalKeypair.generate();
    const mandate = Mandate.issueRoot(
      principal.did(),
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );
    expect(await mandate.verify(principal.publicKeyBytes())).toBe(false);
  });

  it('transitionDecay validates transitions', () => {
    const mandate = Mandate.issueRoot(
      'did:key:zPrincipal',
      'did:key:zAgent',
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );

    mandate.transitionDecay(DecayState.Degraded);
    expect(mandate.decay_state).toBe(DecayState.Degraded);

    expect(() => mandate.transitionDecay(DecayState.Suspended)).toThrow(
      InvalidDecayTransition,
    );
  });
});

describe('MandateChain', () => {
  it('verifies a valid 2-mandate chain', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent1 = await PrincipalKeypair.generate();
    const agent2 = await PrincipalKeypair.generate();
    const ttl = futureDate(2);

    const root = Mandate.issueRoot(
      principal.did(),
      agent1.did(),
      new Scope([searchAction, payAction]),
      DisclosureSet.empty(),
      ttl,
    );
    await root.sign(principal);

    const child = root.delegate(
      agent2.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      futureDate(1),
    );
    await child.sign(agent1);

    const chain = new MandateChain(root);
    chain.push(child);

    await chain.verifyChain([
      principal.publicKeyBytes(),
      agent1.publicKeyBytes(),
    ]);
  });

  it('rejects chain with invalid signature', async () => {
    const principal = await PrincipalKeypair.generate();
    const agent1 = await PrincipalKeypair.generate();
    const other = await PrincipalKeypair.generate();
    const ttl = futureDate(2);

    const root = Mandate.issueRoot(
      principal.did(),
      agent1.did(),
      new Scope([searchAction]),
      DisclosureSet.empty(),
      ttl,
    );
    await root.sign(principal);

    const chain = new MandateChain(root);
    await expect(
      chain.verifyChain([other.publicKeyBytes()]),
    ).rejects.toThrow(ChainVerificationFailed);
  });
});

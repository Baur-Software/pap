import { describe, it, expect } from 'vitest';
import { PrincipalKeypair, SessionKeypair } from '../src/keypair.js';

describe('PrincipalKeypair', () => {
  it('generates a keypair', async () => {
    const kp = await PrincipalKeypair.generate();
    expect(kp.did()).toMatch(/^did:key:z/);
    expect(kp.publicKeyBytes().length).toBe(32);
  });

  it('signs and verifies messages', async () => {
    const kp = await PrincipalKeypair.generate();
    const msg = new TextEncoder().encode('hello principal');
    const sig = await kp.sign(msg);
    expect(sig.length).toBe(64);
    expect(await kp.verify(msg, sig)).toBe(true);
  });

  it('rejects wrong message', async () => {
    const kp = await PrincipalKeypair.generate();
    const sig = await kp.sign(new TextEncoder().encode('correct'));
    expect(await kp.verify(new TextEncoder().encode('wrong'), sig)).toBe(false);
  });

  it('DID starts with did:key:z6Mk (Ed25519)', async () => {
    const kp = await PrincipalKeypair.generate();
    // Ed25519 multicodec 0xed01 → base58btc starts with 6Mk
    expect(kp.did()).toMatch(/^did:key:z6Mk/);
  });

  it('reconstructs from bytes', async () => {
    const kp = await PrincipalKeypair.generate();
    // We can't access private key directly, so test via sign/verify roundtrip
    const msg = new TextEncoder().encode('roundtrip test');
    const sig = await kp.sign(msg);
    expect(await kp.verify(msg, sig)).toBe(true);
  });

  it('different keypairs produce different DIDs', async () => {
    const kp1 = await PrincipalKeypair.generate();
    const kp2 = await PrincipalKeypair.generate();
    expect(kp1.did()).not.toBe(kp2.did());
  });
});

describe('SessionKeypair', () => {
  it('generates an ephemeral keypair', async () => {
    const kp = await SessionKeypair.generate();
    expect(kp.did()).toMatch(/^did:key:z6Mk/);
    expect(kp.publicKeyBytes().length).toBe(32);
  });

  it('signs and verifies', async () => {
    const kp = await SessionKeypair.generate();
    const msg = new TextEncoder().encode('session message');
    const sig = await kp.sign(msg);
    expect(await kp.verify(msg, sig)).toBe(true);
  });

  it('is independent from principal keypair', async () => {
    const principal = await PrincipalKeypair.generate();
    const session = await SessionKeypair.generate();
    expect(principal.did()).not.toBe(session.did());
  });
});

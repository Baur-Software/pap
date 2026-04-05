import { describe, it, expect } from 'vitest';
import { PrincipalKeypair } from '../src/keypair.js';
import { SdJwt } from '../src/credential.js';

describe('SdJwt', () => {
  it('creates an SD-JWT with claim keys', async () => {
    const issuer = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), {
      name: 'Alice',
      nationality: 'Wonderland',
      age: 30,
    });

    expect(jwt.claimKeys()).toContain('name');
    expect(jwt.claimKeys()).toContain('nationality');
    expect(jwt.claimKeys()).toContain('age');
  });

  it('signs and verifies commitment', async () => {
    const issuer = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), {
      name: 'Alice',
      nationality: 'Wonderland',
    });

    await jwt.sign(issuer);
    expect(jwt.signature).toBeTruthy();
    expect(await jwt.verify(issuer.publicKeyBytes())).toBe(true);
  });

  it('verification fails with wrong key', async () => {
    const issuer = await PrincipalKeypair.generate();
    const other = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), { name: 'Alice' });

    await jwt.sign(issuer);
    expect(await jwt.verify(other.publicKeyBytes())).toBe(false);
  });

  it('selectively discloses a subset of claims', async () => {
    const issuer = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), {
      name: 'Alice',
      nationality: 'Wonderland',
      age: 30,
    });
    await jwt.sign(issuer);

    // Disclose only name and age
    const disclosed = jwt.disclose(['name', 'age']);
    expect(disclosed).toHaveLength(2);
    expect(disclosed.map((d) => d.key)).toContain('name');
    expect(disclosed.map((d) => d.key)).toContain('age');

    // Verify each disclosure against the commitment hashes
    const hashes = jwt.getDisclosureHashes();
    for (const d of disclosed) {
      expect(SdJwt.verifyDisclosure(d, hashes)).toBe(true);
    }
  });

  it('disclose returns empty for unknown keys', async () => {
    const issuer = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), { name: 'Alice' });
    await jwt.sign(issuer);

    const disclosed = jwt.disclose(['nonexistent']);
    expect(disclosed).toHaveLength(0);
  });

  it('disclosure hashes are sorted', async () => {
    const issuer = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), {
      z_claim: 'last',
      a_claim: 'first',
      m_claim: 'middle',
    });

    const hashes = jwt.getDisclosureHashes();
    const sorted = [...hashes].sort();
    expect(hashes).toEqual(sorted);
  });

  it('verifyDisclosure rejects tampered disclosure', async () => {
    const issuer = await PrincipalKeypair.generate();
    const jwt = new SdJwt(issuer.did(), { name: 'Alice' });
    await jwt.sign(issuer);

    const hashes = jwt.getDisclosureHashes();
    const disclosed = jwt.disclose(['name']);

    // Tamper with the value
    const tampered = { ...disclosed[0], value: 'Bob' };
    expect(SdJwt.verifyDisclosure(tampered, hashes)).toBe(false);
  });
});

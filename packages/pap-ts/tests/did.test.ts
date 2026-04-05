import { describe, it, expect } from 'vitest';
import { publicKeyToDid, didToPublicKeyBytes, verifyKeyFromDid, createDidDocument } from '../src/did.js';
import { PrincipalKeypair } from '../src/keypair.js';

describe('DID utilities', () => {
  it('roundtrips public key through did:key', async () => {
    const kp = await PrincipalKeypair.generate();
    const pubKey = kp.publicKeyBytes();
    const did = publicKeyToDid(pubKey);
    const recovered = didToPublicKeyBytes(did);
    expect(recovered).toEqual(pubKey);
  });

  it('did:key format is correct', async () => {
    const kp = await PrincipalKeypair.generate();
    const did = publicKeyToDid(kp.publicKeyBytes());
    expect(did).toMatch(/^did:key:z6Mk/);
  });

  it('matches keypair.did() output', async () => {
    const kp = await PrincipalKeypair.generate();
    const did = publicKeyToDid(kp.publicKeyBytes());
    expect(did).toBe(kp.did());
  });

  it('rejects invalid DID prefix', () => {
    expect(() => didToPublicKeyBytes('not-a-did')).toThrow();
    expect(() => didToPublicKeyBytes('did:key:invalidprefix')).toThrow();
  });

  it('verifyKeyFromDid returns same bytes as didToPublicKeyBytes', async () => {
    const kp = await PrincipalKeypair.generate();
    const did = kp.did();
    const a = didToPublicKeyBytes(did);
    const b = verifyKeyFromDid(did);
    expect(a).toEqual(b);
  });
});

describe('DidDocument', () => {
  it('creates a valid DID document', async () => {
    const kp = await PrincipalKeypair.generate();
    const did = kp.did();
    const doc = createDidDocument(did, `z${did.slice(8)}`);
    expect(doc['@context']).toBe('https://www.w3.org/ns/did/v1');
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
    expect(doc.authentication).toHaveLength(1);
  });
});

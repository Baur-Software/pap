import bs58 from 'bs58';

/** Multicodec prefix for Ed25519 public key (0xed01). */
const ED25519_MULTICODEC_0 = 0xed;
const ED25519_MULTICODEC_1 = 0x01;

/** Convert an Ed25519 public key (32 bytes) to a did:key identifier. */
export function publicKeyToDid(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(34);
  prefixed[0] = ED25519_MULTICODEC_0;
  prefixed[1] = ED25519_MULTICODEC_1;
  prefixed.set(publicKey, 2);
  return `did:key:z${bs58.encode(prefixed)}`;
}

/** Extract 32-byte public key from a did:key identifier. */
export function didToPublicKeyBytes(did: string): Uint8Array {
  const zPart = did.replace(/^did:key:z/, '');
  if (zPart === did) {
    throw new Error(`Invalid did:key format: ${did}`);
  }
  const decoded = bs58.decode(zPart);
  if (decoded.length !== 34 || decoded[0] !== ED25519_MULTICODEC_0 || decoded[1] !== ED25519_MULTICODEC_1) {
    throw new Error('Invalid multicodec prefix for Ed25519');
  }
  return decoded.slice(2);
}

/** Verify a did:key is well-formed and return the public key bytes. */
export function verifyKeyFromDid(did: string): Uint8Array {
  return didToPublicKeyBytes(did);
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

/** W3C DID Core 1.0 Document. */
export interface DidDocument {
  '@context': string;
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
}

/** Create a W3C DID Document from a did:key identifier. */
export function createDidDocument(did: string, publicKeyMultibase: string): DidDocument {
  const keyId = `${did}#keys-1`;
  return {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase,
      },
    ],
    authentication: [keyId],
  };
}

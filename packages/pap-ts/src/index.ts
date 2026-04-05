// Encoding utilities
export {
  base64urlEncode,
  base64urlDecode,
  sha256,
  sha256Hash,
  canonicalJson,
  utf8Encode,
  utf8Decode,
} from './encoding.js';

// Error types
export {
  PapError,
  ScopeViolation,
  MandateError,
  DelegationExceedsScope,
  DelegationExceedsTtl,
  ChainVerificationFailed,
  MandateExpired,
  InvalidDecayTransition,
  SessionError,
  InvalidSessionTransition,
  TokenError,
  NonceConsumed,
  TokenTargetMismatch,
  ReceiptError,
  VerificationFailed,
} from './error.js';

// Identity layer
export { PrincipalKeypair, SessionKeypair } from './keypair.js';

// DID utilities
export {
  publicKeyToDid,
  didToPublicKeyBytes,
  verifyKeyFromDid,
  createDidDocument,
} from './did.js';
export type { DidDocument, VerificationMethod } from './did.js';

// Scope and disclosure
export { Scope, DisclosureSet } from './scope.js';
export type { ScopeAction, DisclosureEntry } from './scope.js';

// Mandate and delegation
export { DecayState, canTransitionDecay, Mandate, MandateChain } from './mandate.js';
export type { PaymentProof } from './mandate.js';

// SD-JWT selective disclosure
export { SdJwt } from './credential.js';
export type { Disclosure } from './credential.js';

// Session lifecycle
export {
  SessionState,
  canTransitionSession,
  CapabilityToken,
  Session,
} from './session.js';

// Transaction receipts
export {
  SessionOutcome,
  SessionAttestation,
  TransactionReceipt,
} from './receipt.js';

// Transport layer
export {
  createEnvelope,
  envelopeSignableBytes,
  signEnvelope,
  verifyEnvelope,
  HandshakeClient,
} from './transport.js';
export type { ProtocolMessage, Envelope } from './transport.js';

/** Base error class for all PAP protocol errors. */
export class PapError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'PapError';
  }
}

export class ScopeViolation extends PapError {
  constructor(message: string) {
    super('SCOPE_VIOLATION', message);
  }
}

export class MandateError extends PapError {
  constructor(message: string) {
    super('MANDATE_ERROR', message);
  }
}

export class DelegationExceedsScope extends PapError {
  constructor() {
    super('DELEGATION_EXCEEDS_SCOPE', 'Child scope exceeds parent scope');
  }
}

export class DelegationExceedsTtl extends PapError {
  constructor() {
    super('DELEGATION_EXCEEDS_TTL', 'Child TTL exceeds parent TTL');
  }
}

export class ChainVerificationFailed extends PapError {
  constructor(message: string) {
    super('CHAIN_VERIFICATION_FAILED', message);
  }
}

export class MandateExpired extends PapError {
  constructor() {
    super('MANDATE_EXPIRED', 'Mandate has expired');
  }
}

export class InvalidDecayTransition extends PapError {
  constructor(from: string, to: string) {
    super('INVALID_DECAY_TRANSITION', `Invalid decay transition: ${from} → ${to}`);
  }
}

export class SessionError extends PapError {
  constructor(message: string) {
    super('SESSION_ERROR', message);
  }
}

export class InvalidSessionTransition extends PapError {
  constructor(from: string, to: string) {
    super('INVALID_SESSION_TRANSITION', `Invalid session transition: ${from} → ${to}`);
  }
}

export class TokenError extends PapError {
  constructor(message: string) {
    super('TOKEN_ERROR', message);
  }
}

export class NonceConsumed extends PapError {
  constructor() {
    super('NONCE_CONSUMED', 'Nonce has already been consumed');
  }
}

export class TokenTargetMismatch extends PapError {
  constructor() {
    super('TOKEN_TARGET_MISMATCH', 'Token target DID does not match');
  }
}

export class ReceiptError extends PapError {
  constructor(message: string) {
    super('RECEIPT_ERROR', message);
  }
}

export class VerificationFailed extends PapError {
  constructor() {
    super('VERIFICATION_FAILED', 'Signature verification failed');
  }
}

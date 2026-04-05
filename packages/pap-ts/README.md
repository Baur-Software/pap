# @pap/core

TypeScript reference implementation of the **Principal Agent Protocol** (PAP).

Works in Node.js (≥18) and browsers. Zero novel cryptography — Ed25519 signatures via the audited [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) library.

## Install

```bash
npm install @pap/core
```

## Quick Start

```typescript
import {
  PrincipalKeypair,
  SessionKeypair,
  Mandate,
  Scope,
  DisclosureSet,
  CapabilityToken,
  Session,
  TransactionReceipt,
  SdJwt,
} from '@pap/core';

// Generate identity keypairs
const principal = await PrincipalKeypair.generate();
const agent = await SessionKeypair.generate();

console.log(principal.did()); // did:key:z6Mk...

// Issue a mandate
const mandate = Mandate.issueRoot(
  principal.did(),
  agent.did(),
  new Scope([{ action: 'schema:SearchAction', conditions: {} }]),
  DisclosureSet.empty(),
  new Date(Date.now() + 3600_000).toISOString(),
);
await mandate.sign(principal);

// Selective disclosure
const jwt = new SdJwt(principal.did(), {
  name: 'Alice',
  nationality: 'Wonderland',
});
await jwt.sign(principal);
const disclosed = jwt.disclose(['name']); // reveal only name
```

## Modules

| Module | Description |
|--------|-------------|
| `keypair` | `PrincipalKeypair` (root of trust) and `SessionKeypair` (ephemeral) |
| `did` | `did:key` generation, resolution, W3C DID Documents |
| `scope` | `Scope` (action permissions), `DisclosureSet` (context minimization) |
| `mandate` | `Mandate` issuance, delegation chains, `DecayState` lifecycle |
| `credential` | `SdJwt` selective disclosure (per-claim salt hashing) |
| `session` | `CapabilityToken`, `Session` state machine |
| `receipt` | `TransactionReceipt` co-signing, `SessionAttestation` |
| `transport` | 6-phase handshake `Envelope`, `HandshakeClient` |

## Protocol Invariants

- **Property references only** — receipts never contain property values
- **Ephemeral session DIDs** — unlinked to principal identity
- **Progressive decay** — Active → Degraded → ReadOnly → Suspended
- **Delegation scoping** — child mandates cannot exceed parent scope/TTL
- **No novel cryptography** — Ed25519 + SHA-256 only

## Development

```bash
npm install
npm test          # vitest
npm run typecheck # tsc --noEmit
npm run build     # tsc
```

# @pap/sdk — WebAssembly SDK for the Principal Agent Protocol

Browser-native bindings for the PAP protocol, providing cryptographic primitives and a Fetch-based transport layer for the 6-phase handshake.

## Installation

```bash
npm install @pap/sdk
```

Or build from source:

```bash
wasm-pack build crates/pap-wasm --target bundler --out-dir pkg
```

## Quick Start

```typescript
import init, {
  PrincipalKeypair,
  CapabilityToken,
  TransportSession,
} from '@pap/sdk';

// Initialize the WASM module
await init();

// Generate a principal identity
const principal = PrincipalKeypair.generate();

// Mint and sign a capability token for the target agent
const token = CapabilityToken.mint(
  'did:key:zAgent...',       // target agent DID
  'schema:SearchAction',     // permitted action
  principal.did(),           // issuer (you)
  '2026-06-01T00:00:00Z'    // expiry
);
token.sign(principal);

// Create a transport session and run the 6-phase handshake
const session = new TransportSession('https://agent.example.com');
console.log('Ephemeral session DID:', session.sessionDid());

// Phase 1: Present token
const accepted = await session.presentToken(token);
console.log('Session ID:', session.sessionId());

// Phase 2: Exchange ephemeral DIDs (auto-sends session DID)
await session.exchangeDid();

// Phase 3: Send selective disclosures
await session.sendDisclosures(JSON.stringify([
  { "@type": "schema:SearchAction", "query": "flights to Berlin" }
]));

// Phase 4: Request execution
const result = await session.requestExecution();
console.log('Result:', JSON.parse(result));

// Phase 5: Exchange receipt (auto co-signs with session key)
const receipt = JSON.stringify({
  session_id: session.sessionId(),
  action: "schema:SearchAction",
  timestamp: new Date().toISOString(),
  signatures: []
});
const coSigned = await session.exchangeReceipt(receipt);

// Phase 6: Close session
await session.closeSession();
console.log('Phase:', session.phase()); // "Closed"
```

### One-Call Handshake

For convenience, `runHandshake()` executes all 6 phases in sequence:

```typescript
const session = new TransportSession('https://agent.example.com');
const coSignedReceipt = await session.runHandshake(
  token,
  '[]',          // disclosures (empty for zero-disclosure)
  receiptJson    // receipt to co-sign
);
```

## API Reference

### Transport

| Class | Description |
|-------|-------------|
| `TransportSession` | Drives the 6-phase handshake over the Fetch API |

#### `TransportSession`

| Method | Phase | Returns |
|--------|-------|---------|
| `new(baseUrl)` | — | `TransportSession` |
| `sessionDid()` | — | `string` — ephemeral session DID |
| `phase()` | — | `string` — current phase name |
| `sessionId()` | — | `string \| undefined` — after Phase 1 |
| `receiverSessionDid()` | — | `string \| undefined` — after Phase 1 |
| `lastExecutionResult()` | — | `string \| undefined` — after Phase 4 |
| `presentToken(token)` | 1 | `Promise<string>` — TokenAccepted JSON |
| `exchangeDid()` | 2 | `Promise<string>` — SessionDidAck JSON |
| `sendDisclosures(json)` | 3 | `Promise<string>` — DisclosureAccepted JSON |
| `requestExecution()` | 4 | `Promise<string>` — ExecutionResult JSON |
| `exchangeReceipt(json)` | 5 | `Promise<string>` — ReceiptCoSigned JSON |
| `closeSession()` | 6 | `Promise<string>` — SessionClosed JSON |
| `runHandshake(token, disclosuresJson, receiptJson)` | 1-6 | `Promise<string>` — ReceiptCoSigned JSON |

### Primitives

| Class | Description |
|-------|-------------|
| `PrincipalKeypair` | Root Ed25519 keypair bound to the human principal |
| `SessionKeypair` | Ephemeral single-use session keypair |
| `ScopeAction` | A single Schema.org action reference |
| `Scope` | Deny-by-default set of permitted actions |
| `DisclosureEntry` | Per-type data disclosure rules |
| `DisclosureSet` | Collection of disclosure entries |
| `Mandate` | Signed delegation primitive with decay states |
| `CapabilityToken` | Single-use proof of authorization |
| `Session` | Protocol session state machine |

### Utility Functions

| Function | Description |
|----------|-------------|
| `didToPublicKeyBytes(did)` | Decode `did:key` to 32-byte Ed25519 public key |
| `publicKeyBytesToDid(bytes)` | Encode 32-byte Ed25519 public key to `did:key` |

## Error Handling

All async transport methods throw on failure. Errors include:

- **Phase ordering**: `"cannot exchange DID: current phase is Created, expected TokenPresented"`
- **Token rejection**: `"token rejected: invalid scope"`
- **Protocol errors**: `"protocol error E001: something went wrong"`
- **Network errors**: `"fetch failed: ..."`, `"HTTP 404"`
- **Parse errors**: `"JSON parse failed: ..."`

```typescript
try {
  await session.presentToken(token);
} catch (e) {
  if (e.message.startsWith('token rejected:')) {
    // Handle rejection
  }
}
```

## Testing

```bash
# Run WASM tests in headless Chrome
wasm-pack test --headless --chrome crates/pap-wasm

# Or in Node.js (state machine tests only, no fetch)
wasm-pack test --node crates/pap-wasm
```

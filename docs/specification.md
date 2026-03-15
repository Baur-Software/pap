# Principal Agent Protocol (PAP) Specification

**Version:** 0.1
**Status:** Draft
**Date:** 2026-03-15
**Authors:** Todd Baur (Baur Software)

## Abstract

This document specifies the Principal Agent Protocol (PAP), a
cryptographic protocol for human-controlled agent-to-agent
transactions. PAP establishes a trust model rooted in human
principals, defines hierarchical delegation through signed mandates,
enforces context minimization through selective disclosure at the
protocol level, and provides session ephemerality as a structural
guarantee. The protocol uses no novel cryptographic primitives and
requires no central registry, token economy, or trusted third party.

## Status of This Document

This is a draft specification published for review and
interoperability testing. Implementations SHOULD treat this document
as authoritative for PAP v0.1 behavior. Breaking changes MAY occur
before v1.0.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Conventions and Terminology](#2-conventions-and-terminology)
3. [Trust Model and Threat Model](#3-trust-model-and-threat-model)
4. [Identity Layer](#4-identity-layer)
5. [Mandate Structure and Delegation Rules](#5-mandate-structure-and-delegation-rules)
6. [Session Lifecycle](#6-session-lifecycle)
7. [SD-JWT Disclosure Protocol](#7-sd-jwt-disclosure-protocol)
8. [Protocol Messages and Envelope](#8-protocol-messages-and-envelope)
9. [Marketplace Advertisement Schema](#9-marketplace-advertisement-schema)
10. [Federation Protocol](#10-federation-protocol)
11. [Receipt Format](#11-receipt-format)
12. [Verifiable Credential Envelope](#12-verifiable-credential-envelope)
13. [Extension Points](#13-extension-points)
14. [Transport Binding](#14-transport-binding)
15. [Security Considerations](#15-security-considerations)
16. [IANA and Vocabulary References](#16-iana-and-vocabulary-references)
17. [References](#17-references)

---

## 1. Introduction

### 1.1. Problem Statement

Existing agent-to-agent protocols authenticate agents as platform
entities, not as delegates of human principals. None enforce context
minimization at the protocol level. Disclosure is
implementation-dependent. Session ephemerality is undefined. Economic
models underneath these protocols are compatible with platform
capture through cloud compute metering.

### 1.2. Design Goals

PAP is designed to satisfy the following goals:

1. The human principal is the root of trust for every transaction.
2. Context disclosure is enforced by the protocol, not by policy.
3. Sessions are ephemeral by design; no persistent correlation.
4. Delegation is hierarchical with cryptographically enforced bounds.
5. No novel cryptography, no token economy, no central registry.
6. Any compliant implementation MUST be buildable from this document
   alone, without reference to a specific programming language.

### 1.3. Protocol Overview

A PAP transaction involves:

- A **human principal** who holds a device-bound keypair.
- An **orchestrator agent** operating under a root mandate.
- One or more **downstream agents** operating under delegated mandates.
- A **marketplace** for agent discovery and disclosure filtering.
- A **6-phase session handshake** between pairs of agents.
- **Co-signed receipts** recording property references, never values.

---

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY",
and "OPTIONAL" in this document are to be interpreted as described
in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear
in all capitals, as shown here.

### 2.1. Definitions

**Principal:** A human user who holds the root keypair and is the
ultimate authority over all agent actions taken on their behalf.

**Orchestrator:** An agent that holds the root mandate from the
principal. The orchestrator is the only agent that MAY hold the
principal's full context. It delegates scoped mandates to downstream
agents.

**Mandate:** A signed authorization object that specifies what an
agent is permitted to do, what context it may disclose, and when
the authorization expires.

**Mandate Chain:** An ordered sequence of mandates from root to
leaf, each cryptographically linked to its parent.

**Scope:** The set of actions a mandate permits. Deny-by-default:
an empty scope permits nothing.

**Disclosure Set:** The set of context classes an agent holds and
the conditions under which they may be shared.

**Capability Token:** A single-use, signed authorization to open a
session with a specific agent for a specific action.

**Session DID:** An ephemeral `did:key` identifier generated for a
single session and discarded at session close.

**Receipt:** A co-signed record of a transaction that contains
property type references but never property values.

**Decay State:** The lifecycle state of a mandate as it approaches
or passes its TTL without renewal.

---

## 3. Trust Model and Threat Model

### 3.1. Trust Hierarchy

The PAP trust hierarchy is:

```
Human Principal (device-bound keypair, root of trust)
  +-- Orchestrator Agent (root mandate, full principal context)
       +-- Downstream Agent (task mandate, scoped context)
            +-- Marketplace Agent (own principal chain)
```

The principal's device-bound keypair is the sole root of trust.
Every agent in a transaction MUST carry a cryptographically
verifiable mandate chain traceable to this root.

### 3.2. Trust Assumptions

| Assumption | Verification Method |
|---|---|
| Principal keypair not compromised | WebAuthn device binding (Section 4.3) |
| Orchestrator delegates correctly | Mandate chain verification (Section 5.6) |
| Session keys not leaked | Single-use per session, discarded at close |
| Clocks approximately synchronized | RFC 3339 timestamps; receivers SHOULD reject tokens with skew exceeding implementation-defined thresholds |
| Ed25519 not broken | Cryptographic library security; algorithm agility reserved for future versions |

### 3.3. Threat Model

PAP is designed to defend against the following threats:

**T1. Context profiling.** An adversary correlates a principal's
transactions across sessions to build a behavioral profile.
*Mitigation:* Ephemeral session DIDs (Section 6.3) ensure each
session is cryptographically unlinkable.

**T2. Over-disclosure.** An agent discloses more principal context
than the principal authorized. *Mitigation:* SD-JWT selective
disclosure (Section 7) structurally prevents disclosure of claims
not included in the disclosure set. Marketplace filtering
(Section 9.3) excludes agents whose requirements exceed the
mandate before any session is established.

**T3. Delegation bypass.** A downstream agent acts outside its
delegated scope. *Mitigation:* Scope containment (Section 5.4) and
TTL bounds (Section 5.5) are verified cryptographically at each
level of the mandate chain.

**T4. Replay attacks.** An adversary replays a captured capability
token to open an unauthorized session. *Mitigation:* Nonce
consumption (Section 6.2) ensures each token is single-use.

**T5. Mandate tampering.** An adversary modifies a mandate in the
chain. *Mitigation:* Parent hash binding (Section 5.3) and Ed25519
signatures (Section 5.2) detect any modification.

**T6. Platform capture.** A platform operator accumulates control
over agent transactions through infrastructure dependency.
*Mitigation:* Federated discovery (Section 10), no central
registry, no token economy, principal-held keys.

**T7. Payment linkability.** A payment is correlated with the
principal's identity. *Mitigation:* Chaumian ecash blind-signed
tokens (Section 13.1) provide unlinkable proof of value transfer.

### 3.4. Explicit Non-Goals

The following are explicitly out of scope for PAP:

1. Compatibility with token economy monetization.
2. Enclave-as-equivalent-to-local trust models.
3. Identity recovery through platform operators.
4. Central registries for agent discovery.
5. Runtime scope expansion of mandates.
6. Arbitrary code execution in the orchestrator context.
7. Any extension that trades trust guarantees for adoption ease.

---

## 4. Identity Layer

### 4.1. DID Method

PAP uses the `did:key` method as defined in [DID-KEY]. All
identifiers MUST use Ed25519 public keys with the following
derivation:

```
did:key:z<base58btc(0xed01 || public_key_bytes)>
```

Where:
- `0xed01` is the multicodec prefix for Ed25519 public keys.
- `public_key_bytes` is the 32-byte Ed25519 public key.
- `base58btc` is Bitcoin's base58 encoding.
- The `z` prefix indicates base58btc multibase encoding.

Implementations MUST support `did:key` resolution by extracting
the public key bytes from the DID string:

1. Strip the `did:key:z` prefix.
2. Base58-decode the remainder.
3. Verify the first two bytes are `0xed` and `0x01`.
4. The remaining 32 bytes are the Ed25519 public key.

### 4.2. DID Document

A DID document for a PAP identity MUST conform to [DID-CORE] and
contain:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z...",
  "verificationMethod": [{
    "id": "did:key:z...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z...",
    "publicKeyMultibase": "z<base58btc(public_key_bytes)>"
  }],
  "authentication": ["did:key:z...#key-1"]
}
```

A DID document MUST NOT contain any personal information. It
contains only the public key and verification method reference.

### 4.3. Principal Keypair

The principal keypair is the root of trust. It MUST be an Ed25519
keypair. In production deployments, the private key SHOULD be
bound to a hardware authenticator via WebAuthn [WEBAUTHN].

Implementations MUST support the `PrincipalSigner` interface:

- `did() -> String` -- The `did:key` identifier.
- `sign(message: bytes) -> bytes` -- Ed25519 signature (64 bytes).
- `verifying_key() -> Ed25519PublicKey` -- The public key.

Implementations MAY use software keys for development and testing.
Production deployments SHOULD use WebAuthn-backed keys.

### 4.4. Session Keypair

A session keypair is an ephemeral Ed25519 keypair generated fresh
for each protocol session. Session keypairs:

- MUST be generated using a cryptographically secure random number
  generator.
- MUST NOT be derived from or linked to the principal keypair.
- MUST be discarded when the session closes.
- MUST NOT be persisted to stable storage.

The session DID is derived using the same `did:key` method as the
principal DID. An observer MUST NOT be able to determine whether a
`did:key` identifier represents a principal or a session key.

---

## 5. Mandate Structure and Delegation Rules

### 5.1. Mandate Object

A mandate is the core delegation primitive. It authorizes an agent
to perform specific actions with specific context. A mandate MUST
contain the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `principal_did` | String | REQUIRED | DID of the human principal (root of trust) |
| `agent_did` | String | REQUIRED | DID of the agent receiving this mandate |
| `issuer_did` | String | REQUIRED | DID of the entity signing this mandate |
| `parent_mandate_hash` | String or null | REQUIRED | SHA-256 hash of the parent mandate, or null for root mandates |
| `scope` | Scope | REQUIRED | Permitted actions (Section 5.4) |
| `disclosure_set` | DisclosureSet | REQUIRED | Context classes and sharing conditions (Section 5.4.3) |
| `ttl` | DateTime | REQUIRED | Expiry timestamp (RFC 3339) |
| `decay_state` | DecayState | REQUIRED | Current lifecycle state (Section 5.7) |
| `issued_at` | DateTime | REQUIRED | Issuance timestamp (RFC 3339) |
| `payment_proof` | String or null | OPTIONAL | Payment proof token (Section 13.1) |
| `signature` | String or null | OPTIONAL | Ed25519 signature (base64url-no-pad) |

### 5.2. Mandate Signing

A mandate MUST be signed by the issuer's Ed25519 signing key.

The canonical form for signing MUST be computed as follows:

1. Construct a JSON object containing all mandate fields EXCEPT
   `signature`.
2. DateTime fields MUST be serialized as RFC 3339 strings.
3. Null fields MUST be included as JSON `null`.
4. Serialize the JSON object to bytes.
5. Compute the Ed25519 signature over these bytes.
6. Encode the 64-byte signature using base64url without padding
   (RFC 4648 Section 5, no `=` padding).

The canonical JSON object MUST contain exactly these keys:

```json
{
  "principal_did": "...",
  "agent_did": "...",
  "issuer_did": "...",
  "parent_mandate_hash": null,
  "scope": { ... },
  "disclosure_set": { ... },
  "ttl": "2026-03-15T20:00:00+00:00",
  "issued_at": "2026-03-15T16:00:00+00:00",
  "payment_proof": null
}
```

### 5.3. Mandate Hashing

The mandate hash is used for parent-child linking in delegation
chains. It MUST be computed as:

1. Compute the canonical form (Section 5.2, step 1-4).
2. Apply SHA-256 to the canonical bytes.
3. Encode the 32-byte digest using base64url without padding.

The hash MUST be deterministic: the same mandate MUST always
produce the same hash.

### 5.4. Scope

#### 5.4.1. Scope Object

A scope defines the set of permitted actions. It is deny-by-default:
an agent with an empty scope MUST NOT perform any action.

```json
{
  "actions": [
    {
      "action": "schema:SearchAction",
      "object": "schema:WebPage",
      "conditions": {}
    }
  ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `actions` | Array of ScopeAction | REQUIRED | The permitted actions |

#### 5.4.2. ScopeAction Object

| Field | Type | Required | Description |
|---|---|---|---|
| `action` | String | REQUIRED | Schema.org action type (e.g., `schema:SearchAction`) |
| `object` | String or null | OPTIONAL | Schema.org object type constraint (e.g., `schema:Flight`) |
| `conditions` | Object | OPTIONAL | Protocol-level conditions (key-value pairs). Default: empty object. |

Action and object type references MUST use the `schema:` prefix
for Schema.org vocabulary. Implementations MAY define additional
namespaced prefixes for domain-specific vocabularies.

#### 5.4.3. DisclosureSet Object

The disclosure set defines what context an agent holds and the
conditions for sharing it.

```json
{
  "entries": [
    {
      "type": "schema:Person",
      "permitted_properties": ["schema:name", "schema:nationality"],
      "prohibited_properties": ["schema:email", "schema:telephone"],
      "session_only": true,
      "no_retention": true
    }
  ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `entries` | Array of DisclosureEntry | REQUIRED | The disclosure entries |

#### 5.4.4. DisclosureEntry Object

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | String | REQUIRED | Schema.org type (e.g., `schema:Person`) |
| `permitted_properties` | Array of String | REQUIRED | Properties the agent MAY disclose |
| `prohibited_properties` | Array of String | REQUIRED | Properties the agent MUST NOT disclose |
| `session_only` | Boolean | OPTIONAL | If true, disclosed data is valid only for the session duration. Default: false. |
| `no_retention` | Boolean | OPTIONAL | If true, the receiving party MUST NOT retain disclosed data beyond the session. Default: false. |

Property references MUST use Schema.org property names with the
`schema:` prefix.

**Property Reference Format:** When used in receipts or marketplace
advertisements, a fully qualified property reference is formed as
`{type}.{property}`, e.g., `schema:Person.schema:name`.

#### 5.4.5. Scope Containment

A child scope S_c is **contained by** a parent scope S_p (written
S_c <= S_p) if and only if for every action A_c in S_c, there
exists an action A_p in S_p such that:

1. `A_c.action == A_p.action`
2. If `A_p.object` is non-null, then `A_c.object` MUST equal
   `A_p.object`.
3. If `A_p.object` is null, then `A_c.object` MAY be any value
   (including null).
4. If `A_p.object` is non-null and `A_c.object` is null, the
   containment check MUST fail. A child MUST NOT broaden an object
   constraint.

### 5.5. Delegation Rules

When an agent delegates a mandate to a child agent, the following
rules MUST be enforced:

**R1. Scope Containment:** The child mandate's scope MUST be
contained by the parent mandate's scope (Section 5.4.5). If
scope containment fails, the delegation MUST be rejected.

**R2. TTL Bound:** The child mandate's `ttl` MUST NOT exceed the
parent mandate's `ttl`. If the child TTL exceeds the parent TTL,
the delegation MUST be rejected.

**R3. Parent Hash Binding:** The child mandate's
`parent_mandate_hash` MUST equal the hash (Section 5.3) of the
parent mandate's canonical form.

**R4. Issuer Chain:** The child mandate's `issuer_did` MUST equal
the parent mandate's `agent_did`. The child mandate MUST be signed
by the parent mandate's `agent_did` key.

**R5. Principal Propagation:** The child mandate's `principal_did`
MUST equal the parent mandate's `principal_did`.

**R6. Root Mandate:** A root mandate MUST have
`parent_mandate_hash` set to null. A root mandate's `issuer_did`
MUST equal its `principal_did`.

### 5.6. Mandate Chain Verification

A mandate chain is an ordered array of mandates `[M_0, M_1, ..., M_n]`
where `M_0` is the root mandate. Verification MUST proceed as follows:

1. `M_0.parent_mandate_hash` MUST be null.
2. `M_0.signature` MUST verify against the principal's public key.
3. For each `i` from 1 to n:
   a. `M_i.parent_mandate_hash` MUST equal `hash(M_{i-1})`.
   b. `M_i.scope` MUST satisfy scope containment against
      `M_{i-1}.scope` (Section 5.4.5).
   c. `M_i.ttl` MUST NOT exceed `M_{i-1}.ttl`.
   d. `M_i.signature` MUST verify against the public key of
      `M_{i-1}.agent_did`.

If any check fails, the entire chain MUST be rejected.

### 5.7. Decay State Machine

A mandate's decay state tracks its lifecycle as the TTL progresses.
The decay state MUST be one of:

| State | Description |
|---|---|
| `Active` | Full scope, within TTL |
| `Degraded` | Reduced scope, TTL within decay window, renewal pending |
| `ReadOnly` | No execution permitted, observation only, TTL expired |
| `Suspended` | No activity, awaiting principal review |

#### 5.7.1. State Transitions

The following transitions are valid:

```
Active --> Degraded --> ReadOnly --> Suspended
  ^            |            |
  |            |            |
  +-- renewal -+-- renewal -+
```

| From | To | Condition |
|---|---|---|
| Active | Degraded | Remaining TTL <= implementation-defined decay window |
| Degraded | ReadOnly | TTL expired without renewal |
| ReadOnly | Suspended | Implementation-defined timeout without principal action |
| Degraded | Active | Mandate renewed by issuer |
| ReadOnly | Active | Mandate renewed by issuer |
| Suspended | (none) | Suspended mandates MUST NOT be renewed. Principal MUST issue a new mandate. |

Any transition not listed above MUST be rejected.

#### 5.7.2. Decay Computation

An implementation SHOULD compute the current decay state as:

```
function compute_decay_state(mandate, decay_window_seconds):
  now = current_utc_time()
  if now > mandate.ttl:
    if mandate.decay_state == Suspended:
      return Suspended
    else:
      return ReadOnly
  else:
    remaining = mandate.ttl - now (in seconds)
    if remaining <= decay_window_seconds:
      return Degraded
    else:
      return Active
```

The `decay_window_seconds` parameter is implementation-defined.
Implementations SHOULD document their chosen value.

---

## 6. Session Lifecycle

### 6.1. Session State Machine

A session tracks the state of a transaction between two agents.
The session state MUST be one of:

| State | Description |
|---|---|
| `Initiated` | Capability token presented, awaiting verification |
| `Open` | Handshake complete, session DIDs exchanged |
| `Executed` | Transaction executed within session |
| `Closed` | Session closed, ephemeral keys discarded |

Valid transitions:

```
Initiated --> Open --> Executed --> Closed
    |                                 ^
    +----------> Closed (early) ------+
                     ^
    Open -------> Closed (early) -----+
```

| From | To | Trigger |
|---|---|---|
| Initiated | Open | Session DID exchange completed |
| Initiated | Closed | Early termination (rejection or error) |
| Open | Executed | Action executed |
| Open | Closed | Early termination |
| Executed | Closed | Session close message sent |

Any transition not listed above MUST be rejected.

### 6.2. Capability Token

A capability token is a single-use authorization to open a session.
It MUST contain the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | String | REQUIRED | Unique token identifier (UUID v4) |
| `target_did` | String | REQUIRED | DID of the agent this token authorizes a session with |
| `action` | String | REQUIRED | Schema.org action type this token authorizes |
| `nonce` | String | REQUIRED | Single-use nonce (UUID v4), consumed on session initiation |
| `issuer_did` | String | REQUIRED | DID of the issuing agent (typically the orchestrator) |
| `issued_at` | DateTime | REQUIRED | Issuance timestamp (RFC 3339) |
| `expires_at` | DateTime | REQUIRED | Expiry timestamp (RFC 3339) |
| `signature` | String or null | OPTIONAL | Ed25519 signature (base64url-no-pad) |

#### 6.2.1. Token Signing

The token canonical form MUST be:

```json
{
  "id": "...",
  "target_did": "...",
  "action": "...",
  "nonce": "...",
  "issuer_did": "...",
  "issued_at": "...",
  "expires_at": "..."
}
```

Signing follows the same procedure as mandate signing (Section 5.2).

#### 6.2.2. Token Verification

A receiving agent MUST verify a capability token as follows:

1. `token.target_did` MUST match the receiver's DID.
2. `token.nonce` MUST NOT appear in the receiver's consumed nonce
   set.
3. The current time MUST NOT exceed `token.expires_at`.
4. `token.signature` MUST verify against the public key of
   `token.issuer_did`.

If all checks pass, the receiver MUST immediately add `token.nonce`
to its consumed nonce set. A nonce, once consumed, MUST never be
accepted again.

### 6.3. Six-Phase Handshake

The session handshake consists of six phases. Each phase involves
a message exchange between the initiating agent (I) and the
receiving agent (R).

```
Phase  Direction  Message              Data
-----  ---------  -------------------  --------------------------------
1a     I -> R     TokenPresentation    CapabilityToken
1b     R -> I     TokenAccepted        session_id, receiver_session_did
       R -> I     TokenRejected        reason (terminates handshake)

2a     I -> R     SessionDidExchange   initiator_session_did
2b     R -> I     SessionDidAck        (empty)

3a     I -> R     DisclosureOffer      disclosures (may be empty array)
3b     R -> I     DisclosureAccepted   (empty)

4      R -> I     ExecutionResult      result (Schema.org JSON-LD)

5a     I -> R     ReceiptForCoSign     half-signed TransactionReceipt
5b     R -> I     ReceiptCoSigned      fully co-signed TransactionReceipt

6a     I -> R     SessionClose         session_id
6b     R -> I     SessionClosed        (empty)
```

#### 6.3.1. Phase 1: Token Presentation

The initiating agent presents a signed capability token. The
receiving agent verifies the token (Section 6.2.2).

On acceptance, the receiver MUST:
1. Generate a fresh session keypair (Section 4.4).
2. Create a session in the `Initiated` state.
3. Return a `TokenAccepted` message containing the session ID and
   the receiver's ephemeral session DID.

On rejection, the receiver MUST return a `TokenRejected` message
with a reason string. The handshake terminates.

#### 6.3.2. Phase 2: Ephemeral DID Exchange

The initiating agent generates its own fresh session keypair and
sends a `SessionDidExchange` message containing its session DID.

On receipt, the receiver MUST:
1. Transition the session state from `Initiated` to `Open`.
2. Store the initiator's session DID.
3. Return a `SessionDidAck` message.

After Phase 2, both parties have exchanged ephemeral session DIDs.
All subsequent envelope signatures (Section 8.2) MUST use session
keys.

#### 6.3.3. Phase 3: Disclosure

The initiating agent sends a `DisclosureOffer` containing an array
of SD-JWT disclosures (Section 7). The array MAY be empty for
zero-disclosure sessions.

The receiver MUST:
1. Verify each disclosure against the SD-JWT commitment
   (Section 7.3).
2. Return a `DisclosureAccepted` message.

If disclosure verification fails, the receiver SHOULD return an
`Error` message and close the session.

#### 6.3.4. Phase 4: Execution

The receiver executes the requested action and returns an
`ExecutionResult` message containing a Schema.org JSON-LD result
object.

The session state MUST transition from `Open` to `Executed`.

#### 6.3.5. Phase 5: Receipt Co-Signing

The initiating agent constructs a `TransactionReceipt`
(Section 11), signs it with its session key, and sends it as
`ReceiptForCoSign`.

The receiving agent MUST:
1. Verify the initiator's signature on the receipt.
2. Add its own co-signature using its session key.
3. Return the fully co-signed receipt as `ReceiptCoSigned`.

#### 6.3.6. Phase 6: Session Close

Either party MAY initiate session close by sending a
`SessionClose` message containing the session ID.

On receipt of `SessionClose`, the other party MUST:
1. Return a `SessionClosed` message.
2. Transition the session state to `Closed`.
3. Discard all ephemeral session keys.

After Phase 6, both parties MUST discard their session keypairs.
Session DIDs MUST NOT be reused.

---

## 7. SD-JWT Disclosure Protocol

### 7.1. Overview

PAP uses Selective Disclosure JWT (SD-JWT) as defined in
[SD-JWT-08] for context disclosure during the session handshake.
SD-JWT allows the principal to hold multiple claims but disclose
only those permitted by the mandate.

### 7.2. SD-JWT Object

An SD-JWT MUST contain:

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | String | REQUIRED | DID of the claim issuer (typically the principal) |
| `claims` | Object | REQUIRED (private) | All claims as key-value pairs |
| `salts` | Object | REQUIRED (private) | Per-claim random salts (UUID v4) |
| `signature` | String or null | OPTIONAL | Ed25519 signature over commitment bytes (base64url-no-pad) |

The `claims` and `salts` fields are private to the holder and
MUST NOT be transmitted in their entirety. Only selected
disclosures (Section 7.3) are transmitted.

### 7.3. Disclosure Object

A disclosure reveals a single claim. It MUST contain:

| Field | Type | Required | Description |
|---|---|---|---|
| `salt` | String | REQUIRED | The claim-specific random salt |
| `key` | String | REQUIRED | The claim key |
| `value` | Any JSON value | REQUIRED | The claim value |

### 7.4. Commitment Computation

The SD-JWT commitment is signed to bind all possible disclosures.

1. For each claim `(key, value)` with salt `s`:
   - Construct: `{"salt": s, "key": key, "value": value}`
   - Hash: `SHA-256(JSON_bytes(disclosure))`
   - Encode: base64url-no-pad

2. Collect all hashes and sort lexicographically.

3. Construct commitment bytes:
   ```json
   {
     "issuer": "<issuer_did>",
     "disclosure_hashes": ["<sorted_hash_1>", "<sorted_hash_2>", ...]
   }
   ```

4. Sign: `Ed25519_sign(JSON_bytes(commitment))`

### 7.5. Disclosure Verification

A verifier MUST:

1. Verify the SD-JWT signature over the commitment bytes using the
   issuer's public key.
2. For each received disclosure:
   a. Compute `hash = base64url(SHA-256(JSON_bytes(disclosure)))`.
   b. Verify that `hash` is present in the signed
      `disclosure_hashes` array.

If any disclosure hash is not found in the commitment, the
verification MUST fail.

### 7.6. Zero-Disclosure Sessions

A session MAY proceed with zero disclosures. In this case:

- The `DisclosureOffer` message carries an empty disclosures array.
- The SD-JWT signature MUST still verify (the commitment contains
  hashes for all claims, but none are revealed).
- The receiver MUST accept an empty disclosure set without error.

---

## 8. Protocol Messages and Envelope

### 8.1. Protocol Message Types

All protocol messages are serialized as JSON objects with a `type`
discriminator field. The following message types are defined:

| Type | Phase | Direction | Fields |
|---|---|---|---|
| `TokenPresentation` | 1 | I->R | `token`: CapabilityToken |
| `TokenAccepted` | 1 | R->I | `session_id`: String, `receiver_session_did`: String |
| `TokenRejected` | 1 | R->I | `reason`: String |
| `SessionDidExchange` | 2 | I->R | `initiator_session_did`: String |
| `SessionDidAck` | 2 | R->I | (no fields) |
| `DisclosureOffer` | 3 | I->R | `disclosures`: Array of JSON values |
| `DisclosureAccepted` | 3 | R->I | (no fields) |
| `ExecutionResult` | 4 | R->I | `result`: JSON value (Schema.org JSON-LD) |
| `ReceiptForCoSign` | 5 | I->R | `receipt`: TransactionReceipt |
| `ReceiptCoSigned` | 5 | R->I | `receipt`: TransactionReceipt |
| `SessionClose` | 6 | Either | `session_id`: String |
| `SessionClosed` | 6 | Either | (no fields) |
| `Error` | Any | Either | `code`: String, `message`: String |

### 8.2. Envelope

Protocol messages are transmitted inside an envelope that provides
routing, sequencing, and integrity.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | String | REQUIRED | Unique envelope identifier (UUID v4) |
| `session_id` | String | REQUIRED | Session this envelope belongs to |
| `sender` | String | REQUIRED | DID of the sender |
| `recipient` | String | REQUIRED | DID of the intended recipient |
| `sequence` | Integer | REQUIRED | Monotonically increasing sequence number within the session |
| `payload` | ProtocolMessage | REQUIRED | The protocol message |
| `timestamp` | DateTime | REQUIRED | ISO 8601 timestamp |
| `signature` | Bytes or null | OPTIONAL | Ed25519 signature over signable bytes |

#### 8.2.1. Envelope Signing

The signable bytes for an envelope MUST be computed as:

```
SHA-256(session_id_bytes || sequence_big_endian_8_bytes || payload_json_bytes)
```

Where `||` denotes concatenation and `sequence_big_endian_8_bytes`
is the sequence number as an 8-byte big-endian integer.

Before Phase 2 (DID exchange), the `signature` field MAY be null
because the capability token carries its own signature from the
issuer.

After Phase 2, all envelopes MUST be signed by the sender's
ephemeral session key.

#### 8.2.2. Envelope Verification

The recipient MUST:

1. Verify `recipient` matches its own DID.
2. Verify `sequence` is strictly greater than the last received
   sequence number for this session.
3. If `signature` is present, verify it against the sender's
   session public key.

---

## 9. Marketplace Advertisement Schema

### 9.1. Agent Advertisement

An agent advertisement declares an agent's capabilities, disclosure
requirements, and return types. Advertisements use Schema.org
vocabulary and JSON-LD structure.

| Field | Type | Required | Description |
|---|---|---|---|
| `@context` | String | REQUIRED | MUST be `"https://schema.org"` |
| `@type` | String | REQUIRED | MUST be `"schema:Service"` |
| `name` | String | REQUIRED | Human-readable agent name |
| `provider` | Provider | REQUIRED | Provider organization (Section 9.2) |
| `capability` | Array of String | REQUIRED | Schema.org action types the agent can perform |
| `object_types` | Array of String | REQUIRED | Schema.org object types the agent operates on |
| `requires_disclosure` | Array of String | REQUIRED | Fully qualified property references the agent requires (e.g., `schema:Person.name`) |
| `returns` | Array of String | REQUIRED | Schema.org types the agent returns |
| `ttl_min` | Integer | OPTIONAL | Minimum session TTL in seconds. Default: 300. |
| `signed_by` | String | REQUIRED | DID that signed this advertisement |
| `signature` | String or null | OPTIONAL | Ed25519 signature (base64url-no-pad) |

### 9.2. Provider Object

| Field | Type | Required | Description |
|---|---|---|---|
| `@type` | String | REQUIRED | MUST be `"schema:Organization"` |
| `name` | String | REQUIRED | Organization name |
| `did` | String | REQUIRED | Operator DID |

### 9.3. Disclosure Filtering

A marketplace registry MUST support two query modes:

**Query by action:** Return all advertisements whose `capability`
array contains the requested action type.

**Query by action with disclosure satisfiability:** Return only
advertisements where:
1. The `capability` array contains the requested action type, AND
2. Every entry in `requires_disclosure` is present in the caller's
   available properties list.

This filtering MUST occur before any mandate is issued or session
is established. Agents whose disclosure requirements exceed the
principal's authorization MUST be excluded. The principal MUST
NOT be asked to over-disclose.

### 9.4. Advertisement Signing

The canonical form for advertisement signing MUST include all
fields except `signature`:

```json
{
  "@context": "https://schema.org",
  "@type": "schema:Service",
  "name": "...",
  "provider": { ... },
  "capability": [...],
  "object_types": [...],
  "requires_disclosure": [...],
  "returns": [...],
  "ttl_min": 300,
  "signed_by": "did:key:z..."
}
```

Signing follows the same Ed25519/base64url-no-pad procedure as
mandate signing (Section 5.2).

A marketplace registry MUST reject unsigned advertisements.

### 9.5. Advertisement Hashing

The content hash of an advertisement MUST be computed as:

```
base64url(SHA-256(canonical_bytes))
```

This hash is used for deduplication in federated registries
(Section 10).

---

## 10. Federation Protocol

### 10.1. Overview

Federation enables independent marketplace registries to discover
and share agent advertisements. Federation is peer-to-peer with
no central coordinator.

### 10.2. Registry Peer

A federation peer is identified by:

| Field | Type | Required | Description |
|---|---|---|---|
| `did` | String | REQUIRED | DID of the peer registry operator |
| `endpoint` | String | REQUIRED | HTTP(S) endpoint for federation API calls |
| `last_sync` | DateTime or null | OPTIONAL | Timestamp of last successful sync |

### 10.3. Federation Messages

Federation uses the following message types, discriminated by a
`type` field:

| Type | Direction | Fields | Description |
|---|---|---|---|
| `QueryByAction` | Request | `action`: String | Query for agents supporting an action |
| `QueryResponse` | Response | `advertisements`: Array of AgentAdvertisement | Matching advertisements |
| `Announce` | Request | `advertisement`: AgentAdvertisement | Announce a new local advertisement |
| `AnnounceAck` | Response | `hash`: String, `accepted`: Boolean | Acknowledge announcement |
| `PeerList` | Request | (none) | Request known peer list |
| `PeerListResponse` | Response | `peers`: Array of RegistryPeer | Known peers |

### 10.4. Federation Endpoints

A federation server MUST expose the following HTTP endpoints:

| Method | Path | Request Body | Response Body |
|---|---|---|---|
| GET | `/federation/query?action={action}` | (none) | `QueryResponse` |
| POST | `/federation/announce` | `Announce` | `AnnounceAck` |
| GET | `/federation/peers` | (none) | `PeerListResponse` |

### 10.5. Content-Hash Deduplication

When merging remote advertisements, a federated registry MUST:

1. Compute the content hash of each advertisement (Section 9.5).
2. If the hash already exists in the local seen-hashes set, skip
   the advertisement.
3. If the advertisement has no signature, skip it.
4. Otherwise, register the advertisement and add its hash to the
   seen-hashes set.

This ensures idempotent synchronization and prevents duplicate
entries.

### 10.6. Peer Discovery

A registry MAY discover new peers transitively:

1. Query a known peer's `/federation/peers` endpoint.
2. For each peer in the response not already known, add it to the
   local peer list.

Implementations SHOULD implement rate limiting and SHOULD validate
that newly discovered peers are reachable before adding them.

---

## 11. Receipt Format

### 11.1. Transaction Receipt

A transaction receipt is a co-signed record of a completed session.
Receipts contain property type references only -- never values.

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | String | REQUIRED | Ephemeral session ID (not linked to principal) |
| `action` | String | REQUIRED | Schema.org action type executed |
| `initiating_agent_did` | String | REQUIRED | Ephemeral session DID of the initiator |
| `receiving_agent_did` | String | REQUIRED | Ephemeral session DID of the receiver |
| `disclosed_by_initiator` | Array of String | REQUIRED | Property references disclosed by the initiator |
| `disclosed_by_receiver` | Array of String | REQUIRED | Property references or operator statements from the receiver |
| `executed` | String | REQUIRED | Human-readable description of the action executed |
| `returned` | String | REQUIRED | Human-readable description of the result returned |
| `timestamp` | DateTime | REQUIRED | RFC 3339 timestamp |
| `signatures` | Array of String | REQUIRED | Co-signatures (base64url-no-pad) |

### 11.2. Receipt Signing

The canonical form for receipt signing MUST include all fields
except `signatures`:

```json
{
  "session_id": "...",
  "action": "...",
  "initiating_agent_did": "...",
  "receiving_agent_did": "...",
  "disclosed_by_initiator": [...],
  "disclosed_by_receiver": [...],
  "executed": "...",
  "returned": "...",
  "timestamp": "..."
}
```

### 11.3. Co-Signing Protocol

1. The initiator constructs a receipt from the completed session.
2. The initiator computes `Ed25519_sign(canonical_bytes)` using its
   session key and appends the base64url-no-pad encoded signature
   to `signatures`.
3. The initiator sends the half-signed receipt to the receiver.
4. The receiver verifies the initiator's signature against the
   initiator's session public key.
5. The receiver computes `Ed25519_sign(canonical_bytes)` using its
   session key and appends its signature to `signatures`.
6. The receiver returns the fully co-signed receipt.

### 11.4. Receipt Verification

To verify a co-signed receipt:

1. The `signatures` array MUST contain exactly 2 entries.
2. `signatures[0]` MUST verify against the initiator's session
   public key.
3. `signatures[1]` MUST verify against the receiver's session
   public key.

### 11.5. Privacy Properties

Receipts MUST NOT contain:
- Personal data values (names, emails, etc.)
- SD-JWT claim values
- Raw execution inputs or outputs

Receipts MUST contain only:
- Schema.org property type references (e.g.,
  `schema:Person.schema:name`)
- Operator-defined category references (e.g.,
  `operator:search_executed`)
- Human-readable action/result descriptions

This ensures receipts are auditable by both principals without
revealing the data exchanged in the transaction.

---

## 12. Verifiable Credential Envelope

### 12.1. Overview

PAP mandates MAY be wrapped in a W3C Verifiable Credential (VC)
envelope for interoperability with existing credential ecosystems.
The VC envelope is OPTIONAL; implementations MUST support bare
mandates and MAY additionally support VC-wrapped mandates.

### 12.2. VC Structure

A PAP Verifiable Credential MUST conform to [VC-DATA-MODEL-2.0]:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:<uuid-v4>",
  "type": ["VerifiableCredential", "PAPMandateCredential"],
  "issuer": "<issuer_did>",
  "issuanceDate": "<rfc3339>",
  "expirationDate": "<rfc3339>",
  "credentialSubject": { <mandate_payload> },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<rfc3339>",
    "verificationMethod": "<did>#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base64url-no-pad>"
  }
}
```

The `type` array MUST include both `"VerifiableCredential"` and
`"PAPMandateCredential"` for discoverability.

### 12.3. Credential Signing

The canonical form for VC signing MUST include all fields except
`proof`:

```json
{
  "@context": [...],
  "id": "...",
  "type": [...],
  "issuer": "...",
  "issuanceDate": "...",
  "expirationDate": "..." or null,
  "credentialSubject": { ... }
}
```

The `proofValue` is `base64url(Ed25519_sign(JSON_bytes(canonical)))`.

---

## 13. Extension Points

The following extensions are defined for PAP v0.1. Extensions are
OPTIONAL; a conformant implementation MAY support none, some, or
all of them.

### 13.1. Payment Proof

A mandate MAY carry a `payment_proof` field containing an opaque
payment token. PAP does not define the payment protocol; it defines
the integration point.

Implementations SHOULD use privacy-preserving payment mechanisms
such as Chaumian ecash blind-signed tokens:

```
ecash:blind:v1:mint=<mint_domain>:amount=<value>:token=<blind_token>
```

Properties:
- The vendor receives proof of value transfer (amount, mint, token).
- The vendor MUST NOT be able to identify the payer from the token.
- The token MUST be unlinkable to the principal's identity.
- The payment proof is included in the mandate's canonical form for
  signing.

### 13.2. Payment Proof Verification

A receiving agent that requires payment MUST:
1. Extract the `payment_proof` from the mandate.
2. Verify the proof against the specified mint (out of band).
3. Accept or reject the session based on verification.

The verification protocol between the receiving agent and the mint
is out of scope for this specification.

### 13.3. Continuity Tokens

A continuity token enables stateful relationships across sessions
without requiring the vendor to retain state.

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_type` | String | REQUIRED | Schema.org type describing the encrypted payload shape |
| `vendor_did` | String | REQUIRED | DID of the vendor that issued this token |
| `encrypted_payload` | String | REQUIRED | Vendor-encrypted state (opaque to orchestrator) |
| `ttl` | DateTime | REQUIRED | Expiry timestamp, set by the principal |
| `issued_at` | DateTime | REQUIRED | Issuance timestamp |

#### 13.3.1. Continuity Token Lifecycle

1. At session close, the vendor encrypts its internal state and
   returns it as a continuity token to the orchestrator.
2. The orchestrator stores the token locally. The vendor retains
   nothing.
3. When the principal returns, the orchestrator presents the token
   to the vendor.
4. The vendor decrypts the payload and resumes the relationship.
5. The principal controls the TTL. The vendor MUST NOT set or
   extend the TTL.
6. To sever the relationship, the principal deletes the token. No
   revocation notice is required.

#### 13.3.2. Continuity Token Properties

- The `schema_type` MUST be inspectable by the orchestrator without
  decrypting the payload.
- The vendor MUST NOT be able to write to the continuity token
  without the principal presenting it.
- The encrypted payload format is vendor-defined and opaque to the
  protocol.

### 13.4. Auto-Approval Policies

An auto-approval policy allows the principal to pre-authorize
certain categories of actions without per-transaction approval.

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | String | REQUIRED | Human-readable policy name |
| `scope` | Scope | REQUIRED | Subset of the mandate scope this policy applies to |
| `max_value` | Number or null | OPTIONAL | Maximum transaction value for auto-approval (currency-agnostic) |
| `zero_additional_disclosure` | Boolean | REQUIRED | If true, auto-approve only when zero additional disclosure is required beyond the mandate |
| `authored_at` | DateTime | REQUIRED | Timestamp when the principal authored this policy |

#### 13.4.1. Auto-Approval Constraints

- The policy scope MUST be contained by the mandate scope
  (Section 5.4.5). A policy MUST NOT be more permissive than the
  mandate.
- Policies are principal-authored and orchestrator-enforced. An
  agent MUST NOT trigger a policy change by requesting it.
- `zero_additional_disclosure` defaults to true. When true, the
  orchestrator MUST auto-approve only when the agent's disclosure
  requirements are fully covered by the existing mandate.
- If `max_value` is set and the transaction value exceeds it, the
  orchestrator MUST request explicit principal approval.

---

## 14. Transport Binding

### 14.1. HTTP/JSON Transport

PAP defines an HTTP/JSON transport binding for the 6-phase
handshake. This binding is the default transport for PAP v0.1.
Implementations MAY define additional transport bindings.

### 14.2. Agent Server Endpoints

A receiving agent MUST expose the following HTTP endpoints:

| Method | Path | Phase | Request | Response |
|---|---|---|---|---|
| POST | `/session` | 1 | `TokenPresentation` | `TokenAccepted` or `TokenRejected` |
| POST | `/session/{id}/did` | 2 | `SessionDidExchange` | `SessionDidAck` |
| POST | `/session/{id}/disclosure` | 3 | `DisclosureOffer` | `DisclosureAccepted` |
| POST | `/session/{id}/execute` | 4 | (empty body) | `ExecutionResult` |
| POST | `/session/{id}/receipt` | 5 | `ReceiptForCoSign` | `ReceiptCoSigned` |
| POST | `/session/{id}/close` | 6 | `SessionClose` | `SessionClosed` |

The `{id}` path parameter is the session ID returned in Phase 1.

### 14.3. Agent Handler Interface

Implementations MUST implement a handler interface with the
following operations:

| Operation | Phase | Input | Output |
|---|---|---|---|
| `handle_token` | 1 | CapabilityToken | (session_id, receiver_session_did) |
| `handle_did_exchange` | 2 | session_id, initiator_session_did | () |
| `handle_disclosure` | 3 | session_id, disclosures | () |
| `execute` | 4 | session_id | JSON result |
| `co_sign_receipt` | 5 | TransactionReceipt | TransactionReceipt (co-signed) |
| `handle_close` | 6 | session_id | () |

### 14.4. Endpoint Resolution

Endpoint resolution maps a DID to a transport endpoint URL. In
production, this SHOULD be backed by DID Document `service`
endpoints. Implementations MAY use in-memory registries for
development and testing.

### 14.5. Content Type

All HTTP request and response bodies MUST use `Content-Type:
application/json`. Implementations SHOULD set `Accept:
application/json` on requests.

### 14.6. Error Handling

If a phase handler returns an error, the server MUST respond with
HTTP status 500 and a `ProtocolMessage::Error` payload containing
a `code` and `message`.

If the request body does not match the expected message type for
the endpoint, the server MUST respond with HTTP status 400.

---

## 15. Security Considerations

### 15.1. Cryptographic Algorithms

PAP v0.1 uses exclusively:

- **Ed25519** (RFC 8032) for all signatures.
- **SHA-256** (FIPS 180-4) for all hashes.
- **Base64url without padding** (RFC 4648 Section 5) for all
  binary-to-text encoding.
- **Base58btc** for DID key encoding.

Implementations MUST use these algorithms. Algorithm agility (the
ability to negotiate alternative algorithms) is deferred to future
versions of the specification.

### 15.2. Key Management

- Principal private keys SHOULD be stored in hardware security
  modules or platform authenticators (WebAuthn). They MUST NOT be
  stored in plaintext in configuration files or environment
  variables in production.
- Session private keys MUST be held only in memory for the
  duration of the session. They MUST NOT be persisted to disk.
- Signing keys for agent operators (used to sign advertisements)
  SHOULD be protected with access controls appropriate to the
  deployment environment.

### 15.3. Nonce Management

- Capability token nonces MUST be stored in a consumed-nonce set
  for at least the duration of the token's validity period.
- Implementations SHOULD periodically purge expired nonces to
  prevent unbounded growth of the consumed-nonce set.
- If a receiver restarts and loses its consumed-nonce set, it
  SHOULD reject all tokens issued before the restart by comparing
  `issued_at` against its restart timestamp.

### 15.4. Replay Protection

Multiple layers provide replay protection:

1. **Token nonces:** Each capability token has a UUID v4 nonce
   consumed on first use.
2. **Envelope sequencing:** Sequence numbers are monotonically
   increasing within a session. Out-of-order envelopes MUST be
   rejected.
3. **Token expiry:** Tokens carry an `expires_at` timestamp.
   Expired tokens MUST be rejected.
4. **Session ephemerality:** Session keys are discarded at close.
   A replayed session message cannot be verified against the
   original session keys.

### 15.5. Denial of Service

- Implementations SHOULD rate-limit token presentation requests
  to prevent resource exhaustion from session initiation floods.
- Federation sync operations SHOULD be rate-limited per peer.
- Marketplace registries SHOULD limit the number of advertisements
  per operator DID.

### 15.6. Man-in-the-Middle

- After Phase 2 (DID exchange), all envelopes MUST be signed by
  the sender's session key. An attacker who intercepts envelopes
  cannot forge valid signatures without the session private key.
- The initial token presentation (Phase 1) is protected by the
  orchestrator's signature on the capability token. An attacker
  cannot forge a valid token without the orchestrator's private
  key.
- Implementations SHOULD use TLS for all HTTP transport to protect
  against passive eavesdropping.

### 15.7. Context Leakage

- The `DisclosureOffer` (Phase 3) MUST contain only SD-JWT
  disclosures permitted by the mandate's disclosure set.
- The orchestrator MUST verify that the agent's
  `requires_disclosure` is satisfiable by the mandate before
  issuing a capability token. An agent MUST NOT receive a token
  if its disclosure requirements exceed the principal's
  authorization.
- Receipts MUST NOT contain personal data values (Section 11.5).

### 15.8. Mandate Chain Depth

Implementations SHOULD enforce a maximum mandate chain depth to
prevent resource exhaustion during chain verification. A maximum
depth of 10 is RECOMMENDED.

### 15.9. Clock Skew

- Implementations MUST use UTC for all timestamps.
- Implementations SHOULD tolerate clock skew of up to 30 seconds
  for token expiry and mandate TTL checks.
- Implementations MAY use NTP or similar time synchronization
  protocols to minimize skew.

### 15.10. Canonical JSON Determinism

The security of mandate hashing and signature verification depends
on deterministic JSON serialization. Implementations MUST ensure
that the canonical JSON form produces identical bytes for the same
logical content.

Implementations SHOULD:
- Use a JSON serializer that produces consistent key ordering.
- Represent numbers without unnecessary precision.
- Use RFC 3339 with explicit UTC offset for all timestamps.

If an implementation cannot guarantee deterministic JSON output,
it MUST use an alternative canonical form (e.g., JCS [RFC 8785])
and document the choice.

### 15.11. Attack Surface Summary

| Attack Vector | Mitigation | Spec Section |
|---|---|---|
| Context profiling | Ephemeral session DIDs | 4.4, 6.3.2 |
| Over-disclosure | SD-JWT structural binding + marketplace filtering | 7, 9.3 |
| Replay attacks | Nonce consumption + envelope sequencing | 6.2.2, 8.2.2 |
| Delegation bypass | Scope containment + TTL bounds | 5.4.5, 5.5 |
| Mandate tampering | Parent hash + signature chain | 5.3, 5.6 |
| Platform lock-in | Federated discovery, no central registry | 10 |
| Payment linkability | Chaumian ecash blind-signed tokens | 13.1 |
| Session correlation | Session keys discarded at close | 4.4, 6.3.6 |
| Stale authorization | Decay state machine + non-renewal revocation | 5.7 |
| Advertisement spoofing | Signed advertisements, registry rejects unsigned | 9.4 |

---

## 16. IANA and Vocabulary References

### 16.1. Schema.org Vocabulary

PAP uses Schema.org (https://schema.org) as the vocabulary for
action types, object types, and property references. The following
Schema.org types are referenced in this specification:

**Action Types:**
- `schema:SearchAction` -- Search for information
- `schema:ReserveAction` -- Reserve a resource (flight, hotel, etc.)
- `schema:PayAction` -- Make a payment
- `schema:CheckAction` -- Check a condition or status
- `schema:ReadAction` -- Read a resource

**Object Types:**
- `schema:Flight` -- A flight
- `schema:Lodging` -- Lodging accommodation
- `schema:WebPage` -- A web page

**Entity Types:**
- `schema:Person` -- A person
- `schema:Organization` -- An organization
- `schema:Service` -- A service
- `schema:Order` -- An order
- `schema:Subscription` -- A subscription

**Property References:**
- `schema:name` -- Name of a person or entity
- `schema:email` -- Email address
- `schema:telephone` -- Phone number
- `schema:nationality` -- Nationality

Implementations MAY use additional Schema.org types and properties.
Implementations MAY define additional namespaced vocabularies using
a prefix notation (e.g., `custom:MyAction`). Custom vocabularies
SHOULD be documented.

### 16.2. W3C Standards

| Standard | URI | Usage |
|---|---|---|
| DID Core 1.0 | https://www.w3.org/TR/did-core/ | DID document structure |
| DID Key Method | https://w3c-ccg.github.io/did-method-key/ | `did:key` derivation |
| VC Data Model 2.0 | https://www.w3.org/TR/vc-data-model-2.0/ | Credential envelope |

### 16.3. IETF Standards

| Standard | RFC/Draft | Usage |
|---|---|---|
| RFC 2119 | Key words | Requirement levels |
| RFC 8174 | Key words update | Requirement levels clarification |
| RFC 3339 | Date and Time on the Internet | Timestamp format |
| RFC 4648 | Base Encodings | Base64url encoding |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm | Ed25519 signatures |
| RFC 8785 | JSON Canonicalization Scheme | Canonical JSON (RECOMMENDED) |
| RFC 9458 | Oblivious HTTP | Cloud request unlinkability (future) |
| draft-ietf-oauth-selective-disclosure-jwt-08 | SD-JWT | Selective disclosure |

### 16.4. WebAuthn

| Standard | URI | Usage |
|---|---|---|
| Web Authentication Level 2 | https://www.w3.org/TR/webauthn-2/ | Device-bound key generation |

### 16.5. Multicodec

The Ed25519 public key multicodec prefix is `0xed01` as registered
in the Multicodec table (https://github.com/multiformats/multicodec).

### 16.6. Reserved Namespace Prefixes

| Prefix | Namespace | Authority |
|---|---|---|
| `schema:` | https://schema.org | Schema.org Community |
| `operator:` | Implementation-defined | Agent operator |
| `pap:` | Reserved for future PAP extensions | PAP specification |

---

## 17. References

### 17.1. Normative References

[RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate
Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC 8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in
RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

[RFC 3339] Klyne, G. and C. Newman, "Date and Time on the
Internet: Timestamps", RFC 3339, July 2002.

[RFC 4648] Josefsson, S., "The Base16, Base32, and Base64 Data
Encodings", RFC 4648, October 2006.

[RFC 8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
Signature Algorithm (EdDSA)", RFC 8032, January 2017.

[DID-CORE] Sporny, M., Guy, A., Sabadello, M., and D. Reed,
"Decentralized Identifiers (DIDs) v1.0", W3C Recommendation,
July 2022.

[DID-KEY] Longley, D. and M. Sporny, "The did:key Method v0.7",
W3C Community Group Report.

[SD-JWT-08] Fett, D., Yasuda, K., and B. Campbell,
"Selective Disclosure for JWTs (SD-JWT)", Internet-Draft
draft-ietf-oauth-selective-disclosure-jwt-08.

[VC-DATA-MODEL-2.0] Sporny, M., et al., "Verifiable Credentials
Data Model v2.0", W3C Recommendation.

[WEBAUTHN] Balfanz, D., et al., "Web Authentication: An API for
accessing Public Key Credentials Level 2", W3C Recommendation.

### 17.2. Informative References

[RFC 8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON
Canonicalization Scheme (JCS)", RFC 8785, June 2020.

[RFC 9458] Thomson, M. and C. A. Wood, "Oblivious HTTP",
RFC 9458, January 2024.

---

## Appendix A. Example: Zero-Disclosure Search

This appendix illustrates a complete PAP transaction with zero
personal disclosure.

### A.1. Setup

```
Principal generates keypair -> did:key:zPrincipal
Orchestrator keypair -> did:key:zOrch
Search agent operator keypair -> did:key:zSearch
```

### A.2. Root Mandate

```json
{
  "principal_did": "did:key:zPrincipal",
  "agent_did": "did:key:zOrch",
  "issuer_did": "did:key:zPrincipal",
  "parent_mandate_hash": null,
  "scope": {
    "actions": [{"action": "schema:SearchAction"}]
  },
  "disclosure_set": {"entries": []},
  "ttl": "2026-03-15T20:00:00+00:00",
  "decay_state": "Active",
  "issued_at": "2026-03-15T16:00:00+00:00",
  "payment_proof": null,
  "signature": "<base64url>"
}
```

### A.3. Marketplace Query

```
query_satisfiable("schema:SearchAction", available=[])
  -> [SearchAgent] (requires_disclosure: [])
  -> Filtered out: agents requiring personal disclosure
```

### A.4. Session Handshake

```
Phase 1: Orchestrator -> SearchAgent: TokenPresentation
         SearchAgent -> Orchestrator: TokenAccepted(session_id, recv_did)

Phase 2: Orchestrator -> SearchAgent: SessionDidExchange(init_did)
         SearchAgent -> Orchestrator: SessionDidAck

Phase 3: Orchestrator -> SearchAgent: DisclosureOffer([])
         SearchAgent -> Orchestrator: DisclosureAccepted

Phase 4: SearchAgent -> Orchestrator: ExecutionResult({...})

Phase 5: Orchestrator -> SearchAgent: ReceiptForCoSign(receipt)
         SearchAgent -> Orchestrator: ReceiptCoSigned(receipt)

Phase 6: Orchestrator -> SearchAgent: SessionClose
         SearchAgent -> Orchestrator: SessionClosed
```

### A.5. Receipt

```json
{
  "session_id": "<uuid>",
  "action": "schema:SearchAction",
  "initiating_agent_did": "did:key:zInitSess",
  "receiving_agent_did": "did:key:zRecvSess",
  "disclosed_by_initiator": [],
  "disclosed_by_receiver": ["operator:search_executed"],
  "executed": "schema:SearchAction executed",
  "returned": "schema:SearchResult returned",
  "timestamp": "2026-03-15T16:05:00+00:00",
  "signatures": ["<initiator_sig>", "<receiver_sig>"]
}
```

Zero personal properties disclosed. Both session DIDs are
ephemeral and discarded. The receipt is auditable but contains
no personal data.

---

## Appendix B. Example: Selective Disclosure Flight Booking

### B.1. Disclosure Set

```json
{
  "entries": [{
    "type": "schema:Person",
    "permitted_properties": ["schema:name", "schema:nationality"],
    "prohibited_properties": ["schema:email", "schema:telephone"],
    "session_only": true,
    "no_retention": true
  }]
}
```

### B.2. SD-JWT Claims

```
Claims: {name: "Alice", email: "alice@example.com",
         nationality: "US", telephone: "+1-555-0100"}
Disclosed: [name, nationality]
Withheld: [email, telephone]  (cryptographically uncommitted)
```

### B.3. Marketplace Filtering

```
SkyBook Flight Agent:  requires [name, nationality]    -> satisfiable
LuxAir Premium Agent:  requires [name, nationality, email] -> FILTERED OUT
StayWell Hotel Agent:  wrong object type               -> not matched
```

### B.4. Receipt

```json
{
  "disclosed_by_initiator": [
    "schema:Person.schema:name",
    "schema:Person.schema:nationality"
  ],
  "disclosed_by_receiver": ["operator:booking_confirmed"]
}
```

Values "Alice" and "US" never appear in the receipt.

---

## Appendix C. Example: 4-Level Delegation Chain

```
Level 0: Principal (root of trust)
Level 1: Orchestrator
  scope: [Search, Reserve(Flight), Reserve(Lodging), Pay]
  ttl: 4h

Level 2: Trip Planner (delegated from Orchestrator)
  scope: [Search, Reserve(Flight)]  (subset of Level 1)
  ttl: 3h  (< 4h)
  parent_mandate_hash: hash(Level 1 mandate)

Level 3: Booking Agent (delegated from Trip Planner)
  scope: [Reserve(Flight)]  (subset of Level 2)
  ttl: 2h  (< 3h)
  parent_mandate_hash: hash(Level 2 mandate)
```

Attempted violations:
- Booking Agent delegates PayAction -> DelegationExceedsScope
- Booking Agent delegates with TTL > 2h -> DelegationExceedsTtl

Chain verification: verify_chain([principal_key, orch_key, planner_key])

---

*End of specification.*

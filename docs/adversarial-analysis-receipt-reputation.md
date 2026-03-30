# Adversarial Analysis: Receipt-Based Reputation System

**Date:** 2026-03-30
**Status:** Red-Team Review
**Scope:** Proposed receipt attestation reputation system for PAP federation
**Verdict:** The system as proposed has at least three critical structural vulnerabilities that must be addressed before deployment. Two of these (wash trading and selective attestation) are fundamentally difficult to solve at the protocol level without introducing external trust anchors, which conflicts with PAP's design philosophy.

---

## 0. System Under Analysis

The proposed system adds the following to PAP federation:

1. After session close, the principal's orchestrator publishes a **receipt attestation** -- a signed statement binding a receipt hash to an outcome verdict (`fulfilled`, `partial`, `failed`, `violated_retention`).
2. Attestations are gossiped to federation peers alongside advertisements (via `FederationMessage` variants).
3. Registries compute a **fulfillment ratio** per operator DID: `fulfilled / total`.
4. Marketplace queries gain an optional `min_reputation` filter.

Key protocol facts from the existing codebase (relevant to this analysis):

- Operator DIDs are persistent Ed25519 `did:key` identifiers that sign advertisements (`AgentAdvertisement.signed_by`).
- Session DIDs are ephemeral, generated fresh per session (`SessionKeypair::generate()`), and cryptographically unlinkable to the principal or operator DID.
- Receipts (`TransactionReceipt`) are co-signed by both ephemeral session keys. They contain property references only.
- Federation uses content-hash deduplication (`FederatedRegistry.seen_hashes`) and cryptographic signature verification on advertisements.
- There is no existing mechanism to bind a receipt's ephemeral session DID back to an operator's persistent DID without breaking session unlinkability.
- DID creation is free and instantaneous -- `PrincipalKeypair::generate()` or `SigningKey::generate(&mut OsRng)`.

---

## 1. Attack Tree

```
Receipt-Based Reputation System Attacks
|
+-- 1. INFLATE REPUTATION
|   |
|   +-- 1.1 Wash Trading (self-dealing) [CRITICAL]
|   |   +-- 1.1.1 Sybil DIDs: create N operator DIDs
|   |   +-- 1.1.2 Self-sessions: run sessions between own agents
|   |   +-- 1.1.3 Self-cosign receipts (controls both session keys)
|   |   +-- 1.1.4 Publish "fulfilled" attestations from own orchestrator
|   |   +-- 1.1.5 Gossip to federation peers
|   |
|   +-- 1.2 Receipt Forgery
|   |   +-- 1.2.1 Forge without counterparty key [HARD -- Ed25519]
|   |   +-- 1.2.2 Forge with both endpoints controlled [same as 1.1]
|   |
|   +-- 1.3 Cold Start Gaming [CRITICAL]
|       +-- 1.3.1 Build reputation via trivial zero-disclosure sessions
|       +-- 1.3.2 Pivot to high-sensitivity sessions
|       +-- 1.3.3 Exploit min_reputation filter to appear trustworthy
|
+-- 2. SUPPRESS NEGATIVE SIGNALS
|   |
|   +-- 2.1 Selective Attestation [CRITICAL]
|   |   +-- 2.1.1 Operator suppresses unfavorable attestations
|   |   +-- 2.1.2 Attestation published by principal -- but principal
|   |   |         may not know all federation peers
|   |   +-- 2.1.3 Collude with peer registries to drop attestations
|   |
|   +-- 2.2 Attestation Flooding (dilution)
|       +-- 2.2.1 Flood positive self-attestations
|       +-- 2.2.2 Drown negative signals in noise
|
+-- 3. TRANSFER / LAUNDER REPUTATION
|   |
|   +-- 3.1 Reputation Laundering
|   |   +-- 3.1.1 Build reputation on DID_A
|   |   +-- 3.1.2 Proxy traffic from DID_A to banned DID_B
|   |   +-- 3.1.3 Sell operator DIDs with established reputation
|   |
|   +-- 3.2 DID Rotation Abuse
|       +-- 3.2.1 Burn DID with bad reputation
|       +-- 3.2.2 Generate fresh DID (free, instant)
|       +-- 3.2.3 Start over with clean slate
|
+-- 4. DEGRADE OTHERS' REPUTATION
    |
    +-- 4.1 Grief Attacks
    |   +-- 4.1.1 Malicious principals publish "failed" against honest operators
    |   +-- 4.1.2 Coordinated grief campaign with multiple principal DIDs
    |
    +-- 4.2 Attestation Poisoning
        +-- 4.2.1 Forge attestation messages (requires principal key)
        +-- 4.2.2 Replay old negative attestations
```

---

## 2. Detailed Attack Analysis

### 2.1. Wash Trading

**Feasibility: TRIVIAL**

This is the most dangerous attack against the proposed system.

**Mechanism:**

The attacker performs the following steps, all of which are supported by existing protocol operations with zero external dependencies:

1. Generate N operator keypairs: `SigningKey::generate(&mut OsRng)` -- cost is ~microseconds each.
2. Create and sign advertisements for each operator DID.
3. For each desired "transaction," generate two ephemeral `SessionKeypair`s.
4. Construct a `TransactionReceipt` with the desired property references.
5. Co-sign the receipt with both session keys (attacker controls both).
6. Publish a "fulfilled" attestation from a principal DID the attacker also controls.
7. Gossip the attestation to federation peers.

**Cost to attacker:**

| Resource | Cost |
|----------|------|
| DID generation | ~0 (Ed25519 keygen, microseconds per key) |
| Receipt construction | ~0 (in-memory struct, no external dependency) |
| Co-signing | ~0 (attacker holds both session keys) |
| Attestation publishing | Network cost only (gossip to peers) |
| Compute (1000 fake receipts) | < 1 second on commodity hardware |

**Why this is structurally unfixable in the current design:**

The core problem is that **session DIDs are unlinkable to principal or operator DIDs by design** (spec Section 6.3, threat T1). This is a foundational privacy property of PAP. But it means that when a receipt is co-signed by two ephemeral session DIDs, there is no protocol-level way for a third party to determine whether:

- The two session DIDs belong to genuinely independent parties, or
- A single entity generated both session keypairs.

The privacy guarantee (ephemeral session unlinkability) and the reputation guarantee (independent counterparty attestation) are in fundamental tension. You cannot have both simultaneously without introducing some form of external binding.

**Detection difficulty: HARD**

Since all operations use standard Ed25519 keys in `did:key` format, wash-traded receipts are cryptographically indistinguishable from legitimate ones. Statistical analysis might detect patterns (many sessions between the same operator DIDs, unusually high completion rates, low-complexity sessions), but a sophisticated attacker can vary parameters to evade heuristics.

**Proposed mitigations:**

1. **Stake-weighted reputation (economic Sybil resistance):** Require operators to commit a verifiable economic stake (via the existing Cashu/Lightning payment proof mechanism in spec Section 13.1) before their attestations are counted. The `payment_proof_commitment` field on `TransactionReceipt` already exists. Extend it so that reputation accrual requires a minimum stake per attestation, making wash trading proportionally expensive.

   Spec change: Add to Section 11 a new field `stake_commitment: Option<String>` on receipt attestations. Registries SHOULD weight reputation by cumulative stake rather than raw receipt count.

2. **Cross-principal attestation requirement:** Require that both parties to a receipt independently publish attestations, and that the two attestations reference different principal DIDs (verified via the attestation signature). This does not fully solve the problem (attacker can control multiple principal DIDs), but raises the cost.

   Spec change: Receipt attestations MUST include the attesting principal's DID. Registries MUST count a receipt only when two attestations from distinct principal DIDs reference the same receipt hash.

3. **Session complexity scoring:** Weight reputation by session complexity -- sessions that disclose more properties, involve payment proofs, or chain through delegation hierarchies contribute more reputation than zero-disclosure trivial sessions.

   This is a heuristic defense, not a cryptographic one. It raises the cost of wash trading but does not eliminate it.

4. **TEE-attested session binding (strongest, but optional):** If the `tee` feature is enabled (spec Section 13.6), the session handshake includes `AttestationEvidence` binding the session to a specific enclave. A registry could require TEE attestations for reputation-eligible sessions, making it harder (but not impossible) to fabricate sessions.

---

### 2.2. Receipt Forgery

**Feasibility: IMPRACTICAL (without both keys) / TRIVIAL (with both keys)**

**Without counterparty's session key:**

Forging a receipt requires producing valid Ed25519 signatures for both the initiator and receiver session keys. Given that `TransactionReceipt::verify_both()` checks both signatures against provided verifying keys, and Ed25519 is considered secure against existential forgery under chosen-message attacks (EU-CMA), forging a signature without the corresponding private key is computationally infeasible.

The `canonical_bytes()` method deterministically serializes all receipt fields except signatures, and signatures are verified against those canonical bytes. There is no malleability vector.

**With both endpoints controlled:**

This collapses to wash trading (Section 2.1). The attacker generates both `SessionKeypair`s, constructs the receipt, and calls `co_sign()` twice with their own keys.

**Detection difficulty:** N/A for the infeasible case. For the both-keys case, see wash trading.

**Proposed mitigations:** None needed for the cryptographic case. For the both-keys case, see wash trading mitigations.

---

### 2.3. Selective Attestation

**Feasibility: TRIVIAL**

**Mechanism:**

The proposed system states that "the principal's orchestrator publishes a receipt attestation." This means the publishing entity is the orchestrator controlled by one party to the transaction. The operator (the other party) has limited influence over what gets published -- but the problem works in both directions:

**Operator-side suppression:**
- An operator who also acts as a principal (running their own orchestrator) can simply not publish attestations for sessions where they performed poorly.
- Since attestations are published, not automatically generated by the protocol, there is nothing forcing publication.

**Principal-side suppression:**
- A principal's orchestrator may not know all federation peers.
- The attestation gossip mechanism has no protocol-level guarantee of delivery to all peers.
- An operator could run a federation peer that selectively drops or delays negative attestation messages.

**The fundamental problem:**

Attestation publication is a voluntary, unilateral action. Neither party can force the other to publish. The protocol has no "attestation obligation" mechanism because:

1. The session DID unlinkability guarantee means third parties cannot determine which sessions *should* have attestations.
2. Without a global ledger, there is no consensus on which receipts exist.
3. Federation gossip is best-effort, not guaranteed delivery.

**Cost to attacker:** Zero -- simply do not publish unfavorable attestations.

**Detection difficulty: VERY HARD**

Without a mechanism to enumerate all sessions involving an operator, there is no way to detect missing attestations. The "unknown unknowns" problem: you cannot prove the absence of something you do not know should exist.

**Proposed mitigations:**

1. **Bilateral attestation requirement (protocol-enforced):** Modify the session close protocol (spec Section 6.3.6) so that BOTH parties MUST publish an attestation before the session can cleanly transition to `Closed`. The attestation becomes part of the session lifecycle, not a post-hoc action.

   Spec change: Add a Phase 6 to the session handshake: `AttestationExchange`. Both parties exchange signed attestation commitments. A session that reaches `Executed` but does not complete `AttestationExchange` is recorded as `attestation_missing` -- which registries SHOULD treat as a negative signal.

2. **Attestation commitment before receipt:** During Phase 5 (receipt co-signing), each party commits to an attestation verdict hash (without revealing the verdict). After receipt co-signing completes, both reveal their verdicts. If a party refuses to reveal, the commitment is recorded as evidence of suppression.

   This is a commit-reveal scheme that requires two additional messages in the session protocol.

3. **Peer cross-checking:** Registries periodically cross-reference attestation sets with federation peers. If Peer A has an attestation for operator X that Peer B lacks, Peer B requests it. This does not prevent suppression from the original publisher but limits the effectiveness of selectively gossiping to some peers and not others.

---

### 2.4. Reputation Laundering

**Feasibility: MODERATE**

**Mechanism:**

1. Operator builds legitimate reputation on DID_A through real transactions.
2. Operator publishes a new advertisement under DID_A that actually proxies all traffic to DID_B (a previously banned or low-reputation operator).
3. Alternatively, the operator sells DID_A's signing key to another party (DID transfer is just private key transfer since `did:key` identity IS the keypair per `PrincipalKeypair::from_bytes()`).

**Why this is possible:**

- The `AgentAdvertisement` struct binds a `signed_by` DID to capability claims, but there is no protocol mechanism to verify that the signer actually operates the advertised service.
- The advertisement's `Provider` field is self-asserted.
- DID ownership is proven by key possession alone. Key transfer is out-of-band and undetectable.

**Cost to attacker:** Must first build genuine reputation on DID_A (time cost), then operate the proxy (infrastructure cost).

**Detection difficulty: HARD**

Once a DID's signing key changes hands, the new holder can sign valid advertisements and attestations. There is no cryptographic evidence of the transfer. Behavioral analysis might detect sudden changes in service patterns, but this is heuristic.

**Proposed mitigations:**

1. **Reputation decay over time:** Reputation should decay if not refreshed by recent transactions. A DID that stops transacting for a configurable period (e.g., 30 days) sees its reputation decay toward the cold-start baseline. This limits the value of purchased DIDs.

   Spec change: Fulfillment ratio MUST be computed as a time-weighted moving average with a half-life of `T_decay` (RECOMMENDED: 30 days). Stale reputation converges to unknown, not to the historical peak.

2. **Service continuity probing:** Federation peers MAY periodically probe advertised services to verify they remain operational and consistent with their advertisements. A sudden change in service behavior (different response patterns, latency profiles) SHOULD trigger a reputation flag.

3. **Operator transparency reports:** Optional extension where operators publish signed statements of their infrastructure (endpoint fingerprints, TLS cert fingerprints -- already present in `RegistryPeer.cert_fingerprint`). Changes to infrastructure bindings trigger reputation review periods.

---

### 2.5. Cold Start Gaming

**Feasibility: TRIVIAL**

This is the second most dangerous attack after wash trading.

**Mechanism:**

1. Operator registers with advertisements for low-risk actions (e.g., `schema:SearchAction` with zero disclosure requirements, per `requires_disclosure: vec![]`).
2. Completes many legitimate zero-disclosure sessions with real principals.
3. Each session produces a co-signed receipt. Principals publish "fulfilled" attestations.
4. Operator achieves high fulfillment ratio.
5. Operator updates advertisements to include high-sensitivity actions (e.g., `schema:ReserveAction` requiring `schema:Person.name`, `schema:Person.nationality`).
6. The accumulated reputation from trivial sessions carries over.
7. Principals filtering by `min_reputation` see a high-reputation operator for sensitive actions, despite the reputation having been earned on completely different action types.

**Why this is structurally dangerous:**

The proposed system computes a single fulfillment ratio per operator DID: `fulfilled / total`. This conflates reputation across action types and sensitivity levels. An operator with a 99% fulfillment rate on search queries is treated identically to one with 99% on payment processing.

**Cost to attacker:** Time to build legitimate reputation on trivial sessions (potentially automated).

**Detection difficulty: MODERATE**

Detectable if registries track per-action-type reputation, but undetectable under the proposed flat ratio.

**Proposed mitigations:**

1. **Per-action-type reputation (essential):** Reputation MUST be segmented by Schema.org action type. An operator's fulfillment ratio for `schema:SearchAction` MUST NOT influence their reputation for `schema:ReserveAction`.

   Spec change: Registries MUST maintain per-action fulfillment ratios. The `min_reputation` filter MUST specify the action type. Cross-action reputation MUST NOT be aggregated.

2. **Disclosure-weighted reputation:** Sessions that require and successfully handle personal data disclosure should contribute more to reputation than zero-disclosure sessions. Weight by the number and sensitivity of disclosed property references.

   Spec change: Add a `disclosure_weight` field to attestations, computed as `|disclosed_by_initiator| + |disclosed_by_receiver|`. Reputation for action types requiring disclosure SHOULD weight by disclosure complexity.

3. **Cold-start quarantine period:** New action types advertised by an operator SHOULD have a mandatory cold-start period during which the `min_reputation` filter returns a special `cold_start` status rather than the operator's historical ratio.

---

### 2.6. Attestation Flooding

**Feasibility: MODERATE**

**Mechanism:**

1. Attacker generates thousands of principal DIDs and operator DIDs (cost: ~0).
2. Fabricates sessions and receipts (see wash trading).
3. Floods federation peers with attestation messages.
4. Goals: (a) overwhelm peer processing capacity; (b) dilute real signals with noise; (c) inflate a specific operator's reputation through volume.

**Cost to attacker:** Network bandwidth and the ability to connect to federation peers. DID generation and receipt fabrication are computationally trivial.

**Detection difficulty: MODERATE**

Volume-based detection is possible (anomalous burst of attestations from unknown DIDs), but distinguishing flooding from legitimate high-volume operators requires additional context.

**Proposed mitigations:**

1. **Rate limiting per DID (already implied by spec Section 10.6):** Federation peers MUST rate-limit attestation messages per signing DID. RECOMMENDED: 10 attestations per DID per hour for newly observed DIDs, increasing with age and previous legitimate activity.

2. **Content-hash deduplication (already implemented):** The existing `seen_hashes` mechanism in `FederatedRegistry` prevents duplicate advertisements. Extend this to attestation hashes.

   Spec change: Attestation messages MUST include a content hash. Registries MUST deduplicate by attestation hash using the same mechanism as advertisement dedup (spec Section 10.5).

3. **Proof-of-work or stake requirement for attestation publication:** Require a small proof-of-work or micropayment stake attached to each attestation. This makes flooding proportionally expensive.

4. **Peer trust scoring:** Registries SHOULD track the ratio of valid-to-invalid attestations received from each peer. Peers that forward a high proportion of later-invalidated attestations SHOULD be deprioritized or disconnected.

---

### 2.7. Grief Attacks

**Feasibility: MODERATE**

**Mechanism:**

1. Malicious principal intentionally initiates sessions with a target operator.
2. Completes the session normally (to obtain a valid co-signed receipt).
3. Publishes a "failed" or "violated_retention" attestation against the operator despite the session completing successfully.
4. Optionally: coordinates with multiple Sybil principal DIDs to amplify the effect.

**Why this works:**

The attestation verdict is a unilateral claim by the principal. There is no mechanism for the operator to dispute a false attestation. The receipt proves the session happened and both parties co-signed, but does not prove the outcome verdict.

**Cost to attacker:** Must actually complete sessions with the target operator (time and potential disclosure cost). Sybil amplification requires multiple principal DIDs (free) but multiple actual sessions.

**Detection difficulty: MODERATE**

Detectable through pattern analysis: if a specific set of principal DIDs consistently rates operators negatively while other principals rate them positively, the negative raters may be grief attackers. But this is statistical, not deterministic.

**Proposed mitigations:**

1. **Bilateral attestation with dispute resolution:** If both parties publish attestations and they disagree (principal says "failed," operator says "fulfilled"), the receipt is flagged as `disputed`. Registries SHOULD NOT count disputed receipts toward the fulfillment ratio until resolution.

   Spec change: Add an `operator_attestation` message type. When attestations conflict, the receipt enters `disputed` state. Registries MUST NOT count disputed receipts in either direction.

2. **Principal reputation (symmetric accountability):** Principals also accumulate reputation based on their attestation history. A principal who attests "failed" on most sessions is weighted lower than one with balanced attestation history. This creates mutual accountability.

   Spec change: Registries SHOULD track per-principal attestation distributions. Attestations from principals with anomalous `failed` ratios SHOULD be weighted by `1 / (failed_ratio * k)` where k is a tunable parameter.

3. **Receipt evidence binding:** The attestation MUST include a machine-verifiable evidence field that the registry can check against the receipt. For example, if the attestation claims "violated_retention" but the receipt shows `no_retention: false` in the disclosed properties, the attestation can be automatically invalidated.

4. **Cooldown between sessions with the same operator:** Registries SHOULD limit how frequently the same principal DID can submit attestations against the same operator DID. RECOMMENDED: 1 attestation per principal-operator pair per 24 hours.

---

## 3. Critical Vulnerability Ranking

### Rank 1: Wash Trading (Section 2.1) -- CRITICAL

**Why it is the most dangerous:**

Wash trading undermines the entire foundation of the reputation system. If an operator can inflate their reputation to any desired level at near-zero cost, the `min_reputation` filter becomes security theater. The attack is:

- **Cheap:** Ed25519 keygen + in-memory receipt construction. No real sessions needed.
- **Undetectable:** Cryptographically indistinguishable from legitimate activity.
- **Scalable:** Can generate thousands of fake receipts per second.
- **Structurally enabled:** Session DID unlinkability, a core privacy property, directly enables this attack.

The fundamental tension between privacy (unlinkable sessions) and accountability (verifiable counterparty independence) makes this attack irreducible without design trade-offs.

### Rank 2: Selective Attestation (Section 2.3) -- CRITICAL

**Why it is the second most dangerous:**

Even if wash trading is partially mitigated, selective attestation means the reputation signal is biased. An operator that suppresses 100% of negative attestations shows a 100% fulfillment rate regardless of actual performance. Since attestation is currently proposed as a voluntary, post-session action:

- **Cost: Zero** -- simply do not publish.
- **Detection: Near-impossible** -- you cannot prove the absence of an attestation without knowing which sessions occurred.
- **Impact: Complete** -- the reputation signal becomes unreliable for any operator motivated to suppress.

### Rank 3: Cold Start Gaming (Section 2.5) -- HIGH

**Why it is the third most dangerous:**

This attack exploits a design flaw (flat reputation across action types) rather than a fundamental tension. It is fully solvable through per-action reputation segmentation, but if deployed without this fix, it allows operators to transfer trust earned in low-risk contexts to high-risk contexts. The privacy implications are severe: a principal trusting an operator with sensitive data based on the operator's search-query reputation.

---

## 4. Structural Recommendations

### 4.1. Mandatory Changes Before Deployment

These changes address the critical vulnerabilities and should be implemented before any reputation system goes live.

**R1. Per-action-type reputation segmentation**

Reputation MUST be tracked per `(operator_did, action_type)` pair. The marketplace query `min_reputation` filter MUST specify the action type. This eliminates cold start gaming entirely.

Implementation: Modify the proposed `FederatedRegistry` to maintain a `HashMap<(String, String), ReputationScore>` keyed by `(operator_did, action_type)`.

**R2. Bilateral attestation as part of session lifecycle**

Extend the 6-phase session handshake to include attestation exchange as Phase 6. Both parties commit to attestation verdicts before the session closes. Missing attestations are themselves a signal.

Implementation: Add `AttestationCommit` and `AttestationReveal` variants to the protocol message enum. Extend `SessionState` with an `Attested` state between `Executed` and `Closed`.

**R3. Attestation content-hash deduplication and rate limiting**

Extend the existing `seen_hashes` dedup mechanism to attestation messages. Add per-DID rate limiting for attestation publication.

Implementation: Extend `FederatedRegistry` with `seen_attestation_hashes: HashSet<String>` and `attestation_rate: HashMap<String, (usize, DateTime<Utc>)>`.

### 4.2. Strongly Recommended Changes

These changes significantly improve resilience but involve design trade-offs.

**R4. Economic Sybil resistance via stake requirements**

Require attestations to include a verifiable economic commitment (leveraging the existing `payment_proof_commitment` mechanism). This makes wash trading proportionally expensive rather than free.

Trade-off: Introduces economic barriers to participation. Small operators may be disadvantaged.

**R5. Reputation decay with time-weighted moving average**

Reputation scores decay toward a neutral baseline over time. This limits the value of purchased DIDs, reduces the impact of historical wash trading, and incentivizes ongoing legitimate operation.

Parameters: Half-life of 30 days (configurable per registry). Minimum 10 recent attestations for a score to be considered valid.

**R6. Mutual reputation (principal accountability)**

Track attestation behavior of principals as well as operators. Weight attestations by the attesting principal's own reliability score. This mitigates grief attacks and provides symmetric accountability.

Trade-off: Introduces a secondary reputation system that itself may have the same vulnerabilities (Sybil principals, etc.).

### 4.3. Design Tensions to Acknowledge

The following tensions are inherent in the system design and cannot be fully resolved at the protocol level. They should be documented in the specification as known limitations.

1. **Privacy vs. Accountability:** Session DID unlinkability (spec Section 6.3, threat T1) structurally enables wash trading. Any mechanism that binds sessions to persistent identities for reputation purposes weakens the privacy guarantee. The protocol should make this trade-off explicit and let principals choose their comfort level.

2. **Decentralization vs. Completeness:** Without a global ledger, there is no way to ensure all attestations reach all peers. Selective attestation suppression is possible because federation gossip is best-effort. Introducing guaranteed delivery requires either a consensus mechanism (contradicts "no central registry") or a blockchain (contradicts "no token economy").

3. **Openness vs. Sybil Resistance:** Free DID generation enables permissionless participation (a design goal) but also enables zero-cost Sybil identities. Economic stake requirements add Sybil resistance but create barriers to entry.

---

## 5. Summary Table

| Attack | Feasibility | Cost | Detection | Solvable at Protocol Level? | Recommended Mitigation |
|--------|------------|------|-----------|---------------------------|----------------------|
| Wash Trading | Trivial | ~0 | Hard | Partially (economic cost) | R4: Stake requirement, R5: Decay |
| Receipt Forgery (w/o key) | Impractical | Infeasible | N/A | Already solved (Ed25519) | None needed |
| Receipt Forgery (w/ both keys) | Trivial | ~0 | Hard | Same as wash trading | Same as wash trading |
| Selective Attestation | Trivial | 0 | Very Hard | Partially (bilateral attestation) | R2: Session-lifecycle attestation |
| Reputation Laundering | Moderate | Time + infra | Hard | Partially (decay) | R5: Reputation decay |
| Cold Start Gaming | Trivial | Time | Moderate | Yes | R1: Per-action reputation |
| Attestation Flooding | Moderate | Network | Moderate | Yes | R3: Dedup + rate limiting |
| Grief Attacks | Moderate | Time | Moderate | Partially (bilateral) | R2 + R6: Bilateral + mutual rep |

---

## 6. Conclusion

The proposed Receipt-Based Reputation system has a sound conceptual foundation -- leveraging the existing co-signed receipt mechanism is architecturally elegant. However, the system as described has three critical vulnerabilities (wash trading, selective attestation, cold start gaming) that would render the reputation signal unreliable in adversarial conditions.

The most important insight from this analysis is that **PAP's privacy guarantees (session DID unlinkability) are in fundamental tension with reputation accountability.** This is not a bug; it is an inherent design trade-off. The protocol should acknowledge this tension explicitly and provide a spectrum of reputation modes:

1. **Weak reputation (privacy-maximizing):** No session binding. Reputation is advisory only. Suitable for low-sensitivity actions.
2. **Staked reputation (balanced):** Economic commitments raise the cost of gaming without revealing session identities. Suitable for moderate-sensitivity actions.
3. **TEE-attested reputation (accountability-maximizing):** Sessions include enclave attestations that bind to operator identity. Suitable for high-sensitivity actions where principals demand strong operator accountability.

The six mandatory and recommended changes (R1-R6) collectively address the critical vulnerabilities while preserving PAP's core design philosophy. However, wash trading and selective attestation remain partially mitigable rather than fully solvable at the protocol level -- this should be clearly documented in the specification as a known limitation of any decentralized reputation system that preserves session privacy.

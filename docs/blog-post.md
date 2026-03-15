# Your Agent Works for a Platform. It Should Work for You.

Every agent-to-agent protocol currently in development was designed to serve platform operators, not human principals.

A2A authenticates agents as platform entities. ACP focuses on enterprise workflow interoperability where the principal is the enterprise, not the individual. MCP handles tool-use for a single agent session — it is not a negotiation protocol between agents representing different principals. AgentConnect optimizes for deployment topology, not trust topology.

None of them enforce context minimization at the protocol level. Disclosure is implementation-dependent. None define session ephemerality as a protocol guarantee. All are compatible with token economy monetization. None structurally prevent it.

The trust models are thin. The context controls are voluntary. The session residue is undefined. And the economic model underneath each protocol is cloud compute metering — the same model that turned every previous generation of open standards into a funnel for platform lock-in.

We built something different.

## The Principal Agent Protocol

[PAP](https://github.com/Baur-Software/pap) is designed from the opposite direction. The human principal is the root of trust. Every agent in a transaction carries a cryptographically verifiable mandate from that root. Sessions are ephemeral by design. Context disclosure is enforced by the protocol, not by policy. The cloud is a stateless utility invoked by agents, not a relationship that accumulates principal context.

No new cryptography. No token economy. No central registry.

The repo is open source, written in Rust, and you can clone it and run the end-to-end proof of concept right now.

## The Trust Model

```
Human Principal (device-bound keypair, root of trust)
  └─ Orchestrator Agent (root mandate, full principal context)
       └─ Downstream Agents (scoped task mandates)
            └─ Marketplace Agents (own principal chains)
```

Transactions are handshakes between two mandate chains, not two agents. The orchestrator is the only agent that knows who you are. Every downstream agent knows only what its mandate explicitly permits.

Five constraints are enforced at the protocol level, not the implementation level:

1. **Deny by default.** An agent can only do what its mandate explicitly permits. No scope means no action.
2. **Delegation cannot exceed parent.** A child mandate's scope is bounded by its parent's scope. A child's TTL cannot exceed its parent's TTL. This is verified cryptographically, not by policy.
3. **Session DIDs are ephemeral.** Both agents generate single-use keypairs for each session. These are not linked to any persistent identity. When the session closes, the keys are discarded.
4. **Receipts contain property references only.** A transaction receipt records *what types* of data were disclosed — never the values. Both principals can audit the record. No platform stores it.
5. **Non-renewal is revocation.** A mandate that isn't renewed doesn't need a revocation notice. It degrades progressively — Active, Degraded, ReadOnly, Suspended — and then it stops. The principal sees the degradation, not a surprise cutoff.

## Built on Standards That Already Exist

PAP uses no novel cryptographic primitives. The entire protocol stack is built on existing, standardized specifications maintained by bodies without platform capture:

| Layer | Standard | Purpose |
|-------|----------|---------|
| Identity | WebAuthn | Device-bound keypair generation |
| Identity | W3C DIDs | Decentralized identifiers (`did:key`) |
| Credentials | W3C VC Data Model 2.0 | Mandate envelope |
| Disclosure | SD-JWT (IETF draft-08) | Selective claim disclosure in session handshake |
| Vocabulary | Schema.org | Capability and action type references |
| Data | JSON-LD | Structured linked data for advertisements |
| Privacy | Oblivious HTTP (RFC 9458) | Cloud request unlinkability |

Schema.org describes the *what*. The protocol governs *under what terms*. These are kept strictly separate — no Schema.org extensions, no vocabulary pollution.

## The Implementation

The Rust implementation ships as [four crates](https://github.com/Baur-Software/pap/tree/main/crates) in a Cargo workspace with [four end-to-end examples](https://github.com/Baur-Software/pap/tree/main/examples). 63 tests. All green.

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test
```

What follows is a walk through the examples. Each one exercises protocol features the others do not.

## Example 1: Zero-Disclosure Search

**[`examples/search/src/main.rs`](https://github.com/Baur-Software/pap/blob/main/examples/search/src/main.rs)** — The simplest meaningful transaction that proves the trust model works: a web search with zero personal disclosure.

```bash
cargo run --bin search
```

The example walks through all twelve steps of the protocol handshake. Here's what happens in the code:

The principal generates a keypair and DID document. This is the root of trust — in production it would be backed by WebAuthn, here it's Ed25519 in software ([`crates/pap-did/src/principal.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-did/src/principal.rs)).

```rust
let principal = PrincipalKeypair::generate();
let did_doc = DidDocument::from_keypair(&principal);
```

The principal issues a root mandate to the orchestrator with a single permitted action. Deny by default — if it's not in the scope, it's not allowed. The mandate is signed with the principal's key ([`crates/pap-core/src/mandate.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/mandate.rs)).

```rust
let mut root_mandate = Mandate::issue_root(
    principal_did, orchestrator_did,
    Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
    DisclosureSet::empty(),  // search needs no personal context
    ttl,
);
root_mandate.sign(principal.signing_key());
```

The orchestrator queries the marketplace for agents that can perform `schema:SearchAction` and whose disclosure requirements can be satisfied with zero properties. Agents that need more context than the principal has authorized are filtered out before any mandate is issued ([`crates/pap-marketplace/src/registry.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-marketplace/src/registry.rs)).

```rust
let matches = registry.query_satisfiable("schema:SearchAction", &[]);
```

The orchestrator mints a capability token — a single-use proof bound to the search agent's DID, the action type, and a nonce. The nonce is consumed when the session opens. Replay is structurally impossible ([`crates/pap-core/src/session.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/session.rs)).

```rust
let mut token = CapabilityToken::mint(
    search_operator_did, "schema:SearchAction".into(), orchestrator_did, ttl,
);
token.sign(orchestrator.signing_key());
```

Both agents exchange ephemeral session DIDs — fresh keypairs that are not linked to any persistent identity. When the session closes, these keys are discarded ([`crates/pap-did/src/session.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-did/src/session.rs)).

After execution, both agents co-sign a transaction receipt. The receipt records *what types* of data were disclosed — never values. Both principals can audit the record ([`crates/pap-core/src/receipt.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/receipt.rs)).

```rust
receipt.co_sign(initiator_session.signing_key());
receipt.co_sign(receiver_session.signing_key());
receipt.verify_both(&initiator_session.verifying_key(), &receiver_session.verifying_key())?;
```

The output ends with 14 verified protocol invariants. No platform stored anything. No profile was built. No session token persists. The initiating principal disclosed exactly zero personal properties to complete the transaction.

## Example 2: Travel Booking with Selective Disclosure

**[`examples/travel-booking/src/main.rs`](https://github.com/Baur-Software/pap/blob/main/examples/travel-booking/src/main.rs)** — A flight booking that requires personal context, proving the disclosure controls work under real constraints.

```bash
cargo run --bin travel-booking
```

This example exercises features the search example cannot: what happens when a transaction *requires* personal data.

The principal defines a disclosure profile — what they hold, what they'll share, and what they will never share:

```rust
let disclosure_set = DisclosureSet::new(vec![
    DisclosureEntry::new(
        "schema:Person",
        vec!["schema:name".into(), "schema:nationality".into()],       // permitted
        vec!["schema:email".into(), "schema:telephone".into()],        // prohibited
    )
    .session_only()
    .no_retention(),
]);
```

The mandate is wrapped in a W3C Verifiable Credential envelope ([`crates/pap-credential/src/credential.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-credential/src/credential.rs)). This makes PAP mandates interoperable with existing credential ecosystems.

Three agents are registered in the marketplace:

- **SkyBook Flight Agent** — requires name + nationality. Satisfiable.
- **LuxAir Premium Agent** — requires name + nationality + email. **Filtered out.** The principal prohibits email disclosure. This agent never gets a mandate. The principal is never asked to over-disclose.
- **StayWell Hotel Agent** — wrong object type for this transaction.

```rust
let satisfiable = registry.query_satisfiable("schema:ReserveAction", &available);
// Only SkyBook survives the filter
```

The disclosure exchange uses SD-JWT selective disclosure ([`crates/pap-credential/src/sd_jwt.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-credential/src/sd_jwt.rs)). The principal holds four claims but discloses only two. Email and telephone are cryptographically withheld — the SD-JWT payload structurally cannot reveal them:

```rust
let mut claims = HashMap::new();
claims.insert("schema:name".into(), json!("Alice Baur"));
claims.insert("schema:email".into(), json!("alice@example.com"));
claims.insert("schema:nationality".into(), json!("US"));
claims.insert("schema:telephone".into(), json!("+1-555-0100"));

let mut sd_jwt = SelectiveDisclosureJwt::new(principal_did, claims);
sd_jwt.sign(principal.signing_key());

// Disclose ONLY what the mandate permits
let disclosures = sd_jwt.disclose(&["schema:name", "schema:nationality"]).unwrap();
```

The receipt records `["schema:Person.name", "schema:Person.nationality"]` — property references. The values "Alice Baur" and "US" never appear in the auditable record.

## Example 3: Delegation Chains

**[`examples/delegation-chain/src/main.rs`](https://github.com/Baur-Software/pap/blob/main/examples/delegation-chain/src/main.rs)** — A 4-level mandate hierarchy for a travel orchestrator decomposing a trip into specialized sub-tasks.

```bash
cargo run --bin delegation-chain
```

This example proves the hierarchical trust model works under realistic delegation depth. Four levels, each more restricted than the last:

| Level | Agent | Scope | TTL |
|-------|-------|-------|-----|
| 0 | Human Principal | (root of trust) | — |
| 1 | Orchestrator | Search, Reserve(Flight), Reserve(Lodging), Pay | 4h |
| 2 | Trip Planner | Search, Reserve(Flight) | 3h |
| 3 | Booking Agent | Reserve(Flight) | 2h |

Each delegation is enforced by the protocol. The planner cannot delegate `PayAction` because it doesn't have it. The booking agent cannot delegate anything broader than `ReserveAction(Flight)`:

```rust
let result = booking_mandate.delegate(
    sub_agent.did(),
    Scope::new(vec![ScopeAction::new("schema:PayAction")]),
    DisclosureSet::empty(),
    booking_ttl - Duration::minutes(30),
);
// Err(PapError::DelegationExceedsScope)
```

The full chain — three signed mandates with linked parent hashes — is verified in a single call ([`crates/pap-core/src/mandate.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/mandate.rs)):

```rust
chain.verify_chain(&[
    principal.verifying_key(),
    orchestrator.verifying_key(),
    planner.verifying_key(),
])?;
```

The example also demonstrates decay state transitions. A mandate that isn't renewed doesn't expire suddenly — it degrades: Active → Degraded → ReadOnly → Suspended. The principal sees progressive degradation, not a hard cutoff. Suspended mandates require explicit principal review — there is no automatic restoration.

## Example 4: Payment with Protocol Extensions

**[`examples/payment/src/main.rs`](https://github.com/Baur-Software/pap/blob/main/examples/payment/src/main.rs)** — A digital purchase demonstrating the extensions from PAP spec sections 9.1, 9.3, and 9.4.

```bash
cargo run --bin payment
```

This example exercises three protocol extensions at once: privacy-preserving payment, auto-approval policies, and continuity tokens ([`crates/pap-core/src/extensions.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/extensions.rs)).

The mandate carries a `payment_proof` — a Chaumian ecash blind-signed token. The vendor receives proof of value transfer but nothing that identifies the payer:

```rust
root_mandate.payment_proof = Some(
    "ecash:blind:v1:mint=example.com:amount=50:token=ZGVtby1ibGluZC1zaWduZWQtdG9rZW4".into()
);
```

The principal authors auto-approval policies at setup time. A $12.99 purchase sails through because it's below the $20 threshold. But a policy for `schema:ReserveAction` is rejected — it's not in the mandate scope. An agent cannot trigger a policy change by requesting it:

```rust
let pay_policy = AutoApprovalPolicy::new(
    "Auto-approve small purchases",
    Scope::new(vec![ScopeAction::new("schema:PayAction")]),
).with_max_value(20.0);
pay_policy.validate_against_mandate(&mandate_scope)?;  // OK

let bad_policy = AutoApprovalPolicy::new(
    "Auto-approve reservations",
    Scope::new(vec![ScopeAction::new("schema:ReserveAction")]),
);
bad_policy.validate_against_mandate(&mandate_scope);
// Err(PapError::PolicyExceedsMandate)
```

At session close, the vendor writes an encrypted continuity token and hands it to the orchestrator. The vendor retains nothing. When the principal returns, the orchestrator presents the token; the vendor decrypts it and has full context. The principal controls the TTL — 90 days, not the vendor's preference. Delete the token to sever the relationship:

```rust
let continuity = ContinuityToken::new(
    "schema:Order",
    &vendor_operator_did,
    "encrypted:v1:order_id=DS-2026-0042:items=[pap-spec-pdf]:support_tier=standard",
    Utc::now() + Duration::days(90),  // principal sets the TTL, not the vendor
);
```

## The Crate Structure

Each example above pulls from four crates, each responsible for one layer of the protocol:

| Crate | Source | What It Does |
|-------|--------|-------------|
| [`pap-did`](https://github.com/Baur-Software/pap/tree/main/crates/pap-did) | [`principal.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-did/src/principal.rs), [`session.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-did/src/session.rs), [`document.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-did/src/document.rs) | Ed25519 keypairs, `did:key` derivation, DID documents, ephemeral session keys |
| [`pap-core`](https://github.com/Baur-Software/pap/tree/main/crates/pap-core) | [`scope.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/scope.rs), [`mandate.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/mandate.rs), [`session.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/session.rs), [`receipt.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/receipt.rs), [`extensions.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-core/src/extensions.rs) | Scope, mandates, delegation chains, capability tokens, session state machine, receipts, continuity tokens, auto-approval |
| [`pap-credential`](https://github.com/Baur-Software/pap/tree/main/crates/pap-credential) | [`credential.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-credential/src/credential.rs), [`sd_jwt.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-credential/src/sd_jwt.rs) | W3C VC envelope, SD-JWT selective disclosure |
| [`pap-marketplace`](https://github.com/Baur-Software/pap/tree/main/crates/pap-marketplace) | [`advertisement.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-marketplace/src/advertisement.rs), [`registry.rs`](https://github.com/Baur-Software/pap/blob/main/crates/pap-marketplace/src/registry.rs) | Signed JSON-LD agent advertisements, marketplace registry, disclosure filtering |

## The Capture Test

PAP is designed against a specific threat: incumbent platform capture. Every major internet protocol that started with user sovereignty has been captured by the entities with the largest infrastructure footprint. This is not a conspiracy. It is the predictable outcome of letting the entities with the most to lose from a protocol define its implementation.

XMPP was open and federated until the major messaging platforms stopped federating. OAuth was designed for user authorization until it became the mechanism by which platforms accumulated indefinite permission to act on behalf of users. Every open protocol that required an incumbent's infrastructure to function at scale eventually reflected the incumbent's interests.

Any proposal that routes principal context through infrastructure owned by incumbent platforms is out of scope, regardless of the cryptographic framing around it.

Explicit non-goals: compatibility with token economy monetization. Enclave-as-equivalent-to-local. Identity recovery through platform operators. Payment mechanisms linkable to principal identity. Central registries for agent discovery. Mandate structures allowing runtime scope expansion. UI standards permitting arbitrary code execution in the orchestrator context. Any extension that trades trust guarantees for adoption ease.

Good feedback makes the protocol harder to capture. Proposals that introduce new trusted third parties, centralize discovery, soften disclosure enforcement, or create compatibility with metering models should be evaluated as potential capture vectors first and protocol improvements second.

## What Happens Next

PAP v0.1 is a working architecture specification backed by a working Rust implementation. The protocol flow runs end-to-end across four examples — zero-disclosure search, selective disclosure with SD-JWT, four-level delegation chains, and privacy-preserving payment with continuity. 63 tests cover the full protocol surface. The cryptographic guarantees hold.

What it does not yet have: a network transport layer, federation protocol for marketplace discovery, a WebAuthn integration for production key ceremonies, or a formal RFC submission. Those come next.

The repo is at [github.com/Baur-Software/pap](https://github.com/Baur-Software/pap). Clone it. Run the tests. Run the examples. Read the code. The protocol is in the types, the constraints are in the compiler, and the trust model is in the signatures.

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test                        # 63 tests
cargo run --bin search            # zero disclosure
cargo run --bin travel-booking    # selective disclosure
cargo run --bin delegation-chain  # hierarchical trust
cargo run --bin payment           # extensions
```

If you build agents, the question is not whether your agents can talk to each other. The question is who they answer to.

---

*Todd Baur is the founder of [Baur Software](https://baursoftware.com). PAP v0.1 is published under MIT/Apache-2.0. Comments, objections, and alternative proposals are the point of publishing at draft stage.*

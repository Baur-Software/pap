# PAP: Selective Disclosure + Decaying Permissions
## Complete Proof-of-Concept Runnable Example

This example demonstrates that **selective disclosure at discovery time combined with decaying permissions creates a dynamic, privacy-preserving agent marketplace**.

### What We Prove

The example shows three intertwined concepts working together:

#### 1. Agent Advertisement with Schema.org Vocabulary
- Agents advertise their capabilities as **Schema.org action types** (e.g., `schema:SearchAction`, `schema:ReserveAction`)
- Agents declare **required disclosure properties** (e.g., `schema:Person.name`, `schema:Person.nationality`)
- Advertisements are **cryptographically signed** with the operator's Ed25519 key
- The marketplace rejects unsigned advertisements

**Output from example:**
```
Agent A: Flight Search
  Requires: ["schema:Person.nationality"]

Agent C: Premium Booking (high-sensitivity)
  Requires: ["schema:Person.name", "schema:Person.nationality", "schema:Person.email", "schema:Person.paymentMethod"]
```

#### 2. Selective Disclosure at Discovery Time
The marketplace implements **disclosure satisfiability filtering**:
- Query: `query_satisfiable(action, available_properties)`
- Returns only agents whose `requires_disclosure` can be satisfied
- **Principal is never asked to over-disclose**

**Example proof:**
```
Agent D: International Booking
  Requires: ["schema:Person.nationality", "schema:Person.passportNumber"]
  Satisfiable: NO ✗ (passportNumber not available)
  → Agent filtered out, not returned to principal
```

**Code from `pap-marketplace/src/registry.rs`:**
```rust
pub fn query_satisfiable(
    &self,
    action: &str,
    available_properties: &[String],
) -> Vec<&AgentAdvertisement> {
    self.advertisements
        .iter()
        .filter(|ad| {
            ad.supports_action(action) &&
            ad.disclosure_satisfiable(available_properties)
        })
        .collect()
}
```

#### 3. Selective Disclosure at Mandate Time
- Principal holds 4 properties: name, nationality, email, paymentMethod
- When issuing mandate, principal chooses which to disclose
- Example: Discloses name + nationality + email, but **NOT** payment method
- Properties marked `session_only` decay with mandate TTL

**Output from example:**
```
Disclosed properties to Premium Booking Agent:
  ✓ schema:Person.name
  ✓ schema:Person.nationality
  ✓ schema:Person.email (session-only)

Note: paymentMethod NOT disclosed (even though available)
```

#### 4. Decaying Permissions & Data Decay
As mandate TTL progresses, the state machine transitions:
- **Active** (0-16s remaining): Full scope, session_only properties accessible
- **Degraded** (16-24s remaining, decay window): Reduced scope, renewal pending
- **ReadOnly** (0s remaining): TTL expired, session_only properties inaccessible
- **Suspended**: Terminal state requiring new mandate

**Proof from example:**
```
After 18 seconds: TTL remaining = 6 | State = Degraded
  Agents available: 1

After 25 seconds: TTL remaining = 0 | State = ReadOnly
  ⚠ session_only property 'email' inaccessible (session expired)
  Agents available: 1 (now only: name, nationality)
```

**The Key Innovation:** When permissions decay, the **accessible data scope shrinks dynamically**.

### Running the Example

```bash
cd examples/selective-disclosure-decay
cargo build
./target/debug/selective-disclosure-decay
```

### What Each Phase Demonstrates

**Phase 1:** Principal holds 4 properties
```
✓ schema:Person.name
✓ schema:Person.nationality
✓ schema:Person.email (session-only)
✓ schema:Person.paymentMethod
```

**Phase 2:** Marketplace has 4 agents with different disclosure requirements
```
Agent A: Requires [nationality]                    ← Satisfiable
Agent B: Requires [name, nationality]             ← Satisfiable
Agent C: Requires [name, nationality, email, paymentMethod] ← Satisfiable
Agent D: Requires [nationality, passportNumber]   ← NOT satisfiable (passport not available)
```

**Phase 3:** Principal queries for ReserveAction in Active state
```
Results (only satisfiable agents):
  ✓ Flight Booking Agent
  ✓ Premium Booking Agent
  ✗ International Booking Agent (filtered out)
```

**Phase 4:** Principal issues mandate with selective disclosure
```
Disclosed:   [name, nationality, email]
Not disclosed: [paymentMethod]  ← Principal's choice, even though available
```

**Phase 5:** TTL progression shows dynamic decay
```
Time  │ State    │ session_only accessible? │ Available agents
────────────────────────────────────────────────────────────
0-16s │ Active   │ Yes (email accessible)   │ 1 agent
18s   │ Degraded │ Yes (still active)       │ 1 agent
25s   │ ReadOnly │ No (email expired)       │ 1 agent
```

### Protocol Guarantees Proven

✓ **Structural guarantee:** SD-JWT signature prevents disclosure of claims not in permitted set
✓ **Discovery guarantee:** Agents whose requirements exceed available properties are filtered pre-mandate
✓ **No over-disclosure:** Principal controls exactly what is revealed
✓ **Decay guarantee:** session_only properties become inaccessible when TTL expires
✓ **Anti-platform-capture:** Registry returns results in insertion order (no ranking by metrics)

### Code Components Used

- **`pap-marketplace/src/advertisement.rs`**: Agent advertisement creation, signing, verification
- **`pap-marketplace/src/registry.rs`**: Query by action with disclosure satisfiability filtering
- **`pap-core/src/scope.rs`**: DisclosureSet and DisclosureEntry for mandate selective disclosure
- **`pap-core/src/mandate.rs`**: DecayState enum for permission lifecycle

### Key Insight

This example proves that **selective disclosure + decaying permissions together create a complete privacy-preserving discovery system**:

1. At **discovery time**: Registry filters agents based on what the principal can disclose
2. At **mandate time**: Principal chooses which properties to actually reveal
3. During **session**: Permission state controls data accessibility
4. At **expiration**: session_only data becomes inaccessible, potentially removing agents from available options

The marketplace never forces over-disclosure. The principal maintains control at every step.

---

**Run this example to verify:** Agent discovery, disclosure filtering, selective disclosure, and permission decay all work together as designed.

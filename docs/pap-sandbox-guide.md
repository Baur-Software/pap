# PAP Sandbox: Execution Isolation & Capability Attestation

Agents execute with **OS-level capability enforcement** and **cryptographic proof** of what was allowed to happen.

## The Problem: Complete Security Requires Two Boundaries

PAP's **request boundary** (SD-JWT selective disclosure) controls *what an agent can see*. But even perfectly scoped data doesn't prevent damage if the agent itself is compromised or the code inside it is malicious.

**Execution isolation solves the second half**: minimize *what the agent can actually do*.

- **Before sandbox**: Agent runs in Papillon's process space. If exploited, attacker gets network access, filesystem access, subprocess spawning—the whole system.
- **After sandbox**: Agent runs in restricted child process. Network blocked. Filesystem restricted. Subprocess spawning prevented. Even if code is injected, the OS constraints prevent escape.

Together they seal the entire attack surface: minimum data surface + maximum execution constraints.

## How Papillon Uses It

When you submit a prompt in Papillon, the block lifecycle includes execution isolation:

```
Resolving (6-phase handshake)
  ↓
AwaitingApproval (shows disclosure scope + execution constraints)
  → Seccomp rules: "socket blocked, file access restricted to /tmp"
  → Timeout: "execution must complete within 30s"
  ↓ (user clicks APPROVE)
Executing (block runs in sandbox)
  → Child process spawned with restrictions applied
  → Agent sees only disclosed properties
  → Network/filesystem/subprocess calls blocked by OS
  ↓
Resolved (receipt includes attestation)
  → Block displays result + capability proof
  → Receipt shows: seccomp_rules_hash, timeout_enforced_secs, exit_code
  → Principal's co-signature proves constraints were applied
```

The **AttestationReceipt** is a cryptographic record: "This agent ran under these exact constraints, signed by the principal."

## How Chrysalis Uses It

In the registry (`apps/registry`), each agent has a **per-agent sandbox toggle**:

1. **Enable sandbox (default)**: Agent executes in isolated process with seccomp/pledge/entitlements
   - Stored in KV settings table with key `sandbox_enabled:{agent_hash}`
   - User controls via checkbox in registry UI: "🔒 Sandbox*"
   - Persists across registry restarts
   
2. **Disable sandbox**: Agent executes directly (no isolation, no attestation)
   - Used for trusted internal agents where isolation overhead isn't needed
   - Still generates receipt, but capability constraints are empty/unrestricted

The asterisk (`*`) indicates restart required to apply—capability changes take effect after the registry process restarts.

## Configuration: Policy Cascade

Every agent's execution is governed by **CapabilityPolicy**, resolved via a three-tier cascade:

```
Agent-specific override (highest priority)
  ↓ [if not set, fall through]
Category default (e.g., "external-api" vs. "local")
  ↓ [if not set, fall through]
Global default (hardcoded minimums, lowest priority)
```

**Example cascade for an external hotel booking API:**

```yaml
Global Default:
  execution_timeout_secs: 60
  network_allowed: false
  filesystem_allowed: false

Category Override (external-api):
  network_allowed: true  # override global: allow networking
  filesystem_allowed: false  # inherit global

Agent Override (hotel-api):
  execution_timeout_secs: 30  # override category: tighter timeout
  network_allowed: true  # inherit category
```

**Result**: Hotel agent gets 30s timeout (not 60), network access (allowed for bookings), but no filesystem access.

## Reading Attestation Receipts

Every execution block includes an **AttestationReceipt**. To verify constraints were applied:

1. **Locate the receipt** in the block's metadata (Papillon UI: right-click block → "View Receipt")

2. **Parse the CapabilityProof**:
   ```json
   {
     "session_id": "sid:xyz123",
     "agent_did": "did:key:z6Mk...",
     "execution_duration_ms": 1250,
     "exit_code": 0,
     "capability_enforcement": {
       "seccomp_rules_hash": "abc123def456...",
       "pledge_promises": null,
       "timeout_enforced_secs": 30,
       "memory_protection": {
         "mlock_applied": true,
         "encryption_used": true,
         "sensitive_buffers_wiped": true
       }
     }
   }
   ```

3. **Verify the signature**: Extract principal's Ed25519 signature from receipt and verify against the receipt content (Python: `pap.verify_receipt_signature(receipt, principal_did)`)

4. **Audit properties**:
   - `seccomp_rules_hash` (Linux) matches the policy you approved
   - `timeout_enforced_secs` was respected (execution_duration_ms < timeout)
   - `mlock_applied: true` means sensitive data stayed in RAM
   - `exit_code` shows how execution ended (0 = success, timeout = killed by enforcer)

## Platform Support

Sandbox execution is portable across all major platforms:

| Platform | Isolation Mechanism | Proof Field | Overhead |
|----------|-------------------|-------------|----------|
| **Linux** | seccomp (BPF) | `seccomp_rules_hash` | ~2-5% |
| **BSD** | pledge(2) | `pledge_promises` | ~1-3% |
| **macOS** | Entitlements + sandbox | `entitlements_applied` | ~5-8% |
| **Windows** | Job Objects | job limits in receipt | ~3-6% |

On unsupported platforms or if sandbox fails to load, the agent falls back to unsandboxed execution but still generates a receipt with a warning field for audit visibility.

## Threat Model: What It Solves & What It Doesn't

### ✅ Solves (Execution Compromise)

- **Filesystem exfiltration**: Sandboxed agent can't read files outside its authorized scope
- **Network exploitation**: Blocked syscalls prevent outbound connections unless explicitly allowed
- **Privilege escalation**: Child process runs with restricted capabilities, can't gain root or CAP_*
- **Resource exhaustion**: CPU/memory limits enforced via policy (tunable per agent)
- **Fork bombs**: Subprocess spawning blocked by capability policy
- **Core dumps**: Core dump capture prevented (RLIMIT_CORE=0)

### ❌ Doesn't Solve (Payload Attacks)

PAP sandbox does NOT prevent:

- **Prompt injection in the request**: If the disclosed payload itself is malicious JSON, the sandbox won't catch it. But the *blast radius* is constrained—the agent sees only the fields you disclosed, and can't do much with them.
- **Logic bugs in agent code**: A buggy search algorithm is still buggy in the sandbox. The sandbox prevents *system compromise*, not *algorithmic mistakes*.
- **Side-channel attacks**: Timing attacks or speculative execution exploits may still work (depends on OS/CPU).

The sandbox is a **containment boundary**, not a validation boundary. It assumes the agent code itself is trustworthy (or at least, that its damage should be constrained).

## Enabling/Disabling in Code

### Papillon (Rust)

Sandbox is enabled by default in production. To disable for a specific agent:

```rust
// In your agent policy configuration
let policy = CapabilityPolicy {
    execution_timeout_secs: 60,
    network_allowed: false,
    filesystem_allowed: false,
    // ... other fields
};

// Pass to SandboxedHandlerWrapper
let wrapper = SandboxedHandlerWrapper::new(
    handler,
    spawner,
    policy,
    true,  // sandbox_enabled = true (default)
    agent_did,
    agent_name,
    action_type,
);
```

### Chrysalis (UI)

Click the `☑ Sandbox*` checkbox in the agent card. Changes persist in the KV settings table but require registry restart to take effect.

### Python SDK

```python
from pap import CapabilityPolicy, CapabilityEnforcer

policy = CapabilityPolicy(
    execution_timeout_secs=30,
    network_allowed=True,
    filesystem_allowed=False,
)

enforcer = CapabilityEnforcer(policy)
result = enforcer.execute(agent_fn, context)
```

## Verification Checklist

After deploying pap-sandbox:

- [ ] Seccomp rules load on Linux (check: `auditctl -l` shows PAP_* rules, or dmesg for SECCOMP_RET_KILL events)
- [ ] Pledge enforces on BSD (test: sandboxed agent tries network → EPERM)
- [ ] Receipts include CapabilityProof with non-empty seccomp_rules_hash / pledge_promises
- [ ] Principal signature verifies on receipt
- [ ] Timeout enforcement works: 1s timeout kills 10s-sleep agent, receipt shows exit_code indicating kill
- [ ] Registry toggle persists: disable sandbox, restart, verify toggle is still off
- [ ] Concurrent executions have no crosstalk: 10 agents running simultaneously produce 10 independent receipts

---

**See also:**
- [pap-sandbox API Reference](../crates/pap-sandbox/README.md)
- [PAP Specification: Security Considerations](./specification.md#15-security-considerations)
- [Papillon Canvas Lifecycle](./CANVAS_SPEC.md)
